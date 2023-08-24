package pingtunnel

import (
	"net"
	"sync"
	"time"

	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/frame"
	"github.com/esrrhs/gohome/loggo"
	"github.com/esrrhs/gohome/threadpool"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/icmp"
)

func NewServer(key int, maxconn int, maxprocessthread int, maxprocessbuffer int, connectTimeout int) (*Server, error) {
	s := &Server{
		exit:             false,
		key:              key,
		maxconn:          maxconn,
		maxprocessthread: maxprocessthread,
		maxprocessbuffer: maxprocessbuffer,
		connectTimeout:   connectTimeout,
	}

	if maxprocessthread > 0 {
		s.processtp = threadpool.NewThreadPool(maxprocessthread, maxprocessbuffer, func(v interface{}) {
			packet := v.(*Packet)
			s.processDataPacket(packet)
		})
	}

	return s, nil
}

type Server struct {
	exit             bool
	key              int
	workResultLock   sync.WaitGroup
	maxconn          int
	maxprocessthread int
	maxprocessbuffer int
	connectTimeout   int

	conn *icmp.PacketConn

	localConnMap sync.Map
	connErrorMap sync.Map

	sendPacket       uint64
	recvPacket       uint64
	sendPacketSize   uint64
	recvPacketSize   uint64
	localConnMapSize int

	processtp   *threadpool.ThreadPool
	recvcontrol chan int
}

type ServerConn struct {
	exit           bool
	timeout        int
	ipaddrTarget   *net.UDPAddr
	conn           *net.UDPConn
	tcpaddrTarget  *net.TCPAddr
	tcpconn        *net.TCPConn
	id             string
	activeRecvTime time.Time
	activeSendTime time.Time
	close          bool
	rproto         int
	fm             *frame.FrameMgr
	tcpmode        int
	echoId         int
	echoSeq        int
}

// Run 启动服务端程序
func (p *Server) Run() error {

	// 启动 icmp 服务
	conn, err := icmp.ListenPacket("ip4:icmp", "")
	if err != nil {
		loggo.Error("Error listening for ICMP packets: %s", err.Error())
		return err
	}
	p.conn = conn
	recv := make(chan *Packet, 10000)
	p.recvcontrol = make(chan int, 1)

	// icmp 数据包 channel
	go func() {
		defer common.CrashLog()

		p.workResultLock.Add(1)
		defer p.workResultLock.Done()
		recvICMP(&p.exit, *p.conn, recv)
	}()

	go func() {
		// statistic 数据统计
		defer common.CrashLog()

		p.workResultLock.Add(1)
		defer p.workResultLock.Done()

		for !p.exit {
			// 关闭并清除超时连接
			p.checkTimeoutConn()
			// 统计并打印流量和连接数据
			p.showNet()
			// 清除异常连接
			p.updateConnError()
			// 每秒执行一次
			time.Sleep(time.Second)
		}
	}()

	go func() {
		// 处理收到的解析后的 icmp 数据包 Packet
		defer common.CrashLog()

		p.workResultLock.Add(1)
		defer p.workResultLock.Done()

		// 控制处理逻辑是否退出，还是轮询退出
		// exit 也可以搞成 channel，要不然每次循环都要判断，很浪费
		for !p.exit {
			select {
			case <-p.recvcontrol:
				return
			case r := <-recv:
				p.processPacket(r)
			}
		}
	}()

	return nil
}

func (p *Server) Stop() {
	p.exit = true
	p.recvcontrol <- 1
	// 同时收到 recvcontrol 和 recv，recv 可能会被丢了
	p.workResultLock.Wait()
	p.processtp.Stop()
	p.conn.Close()
}

func (p *Server) processPacket(packet *Packet) {

	// 认证，明文认证，包里的 key 和启动时配置的 key 配的上就行
	if packet.my.Key != (int32)(p.key) {
		return
	}

	// ping 方法，直接返回给客户端
	if packet.my.Type == (int32)(MyMsg_PING) {
		t := time.Time{}
		t.UnmarshalBinary(packet.my.Data)
		loggo.Info("ping from %s %s %d %d %d", packet.src.String(), t.String(), packet.my.Rproto, packet.echoId, packet.echoSeq)
		sendICMP(packet.echoId, packet.echoSeq, *p.conn, packet.src, "", "", (uint32)(MyMsg_PING), packet.my.Data,
			(int)(packet.my.Rproto), -1, p.key,
			0, 0, 0, 0, 0, 0,
			0)
		return
	}

	// kick 方法，下线操作
	if packet.my.Type == (int32)(MyMsg_KICK) {
		localConn := p.getServerConnById(packet.my.Id)
		if localConn != nil {
			p.close(localConn)
			loggo.Info("remote kick local %s", packet.my.Id)
		}
		return
	}

	// 处理数据包，如果开了并发就丢到消费队列里，没有开并发就串行处理
	if p.maxprocessthread > 0 {
		p.processtp.AddJob((int)(common.HashString(packet.my.Id)), packet)
	} else {
		p.processDataPacket(packet)
	}
}

// 为新的 id 创建新的连接
func (p *Server) processDataPacketNewConn(id string, packet *Packet) *ServerConn {

	now := common.GetNowUpdateInSecond()

	loggo.Info("start add new connect  %s %s", id, packet.my.Target)

	if p.maxconn > 0 && p.localConnMapSize >= p.maxconn {
		// 当设置了最大连接数，且本地已有连接数大于等于最大连接数，选择抛弃新的连接，而不是把旧的连接杀掉，可以考虑用 lru
		loggo.Info("too many connections %d, server connected target fail %s", p.localConnMapSize, packet.my.Target)
		p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src)
		return nil
	}

	addr := packet.my.Target
	// 如果这个地址之前尝试过连接而且还是失败了，会放到 errorConnMap 里，被放进这个 map 里的地址在 5 秒内都不会重新连接，5 秒后才能重新尝试连接
	if p.isConnError(addr) {
		loggo.Info("addr connect Error before: %s %s", id, addr)
		p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src)
		return nil
	}

	// 决定通过什么协议转发是通过数据包里的 TcpMode 定的
	if packet.my.Tcpmode > 0 {
		// 建立 tcp 连接
		c, err := net.DialTimeout("tcp", addr, time.Millisecond*time.Duration(p.connectTimeout))
		if err != nil {
			// 建立不好，打印日志，返回 icmp 的 kick 消息，把 addr 加到 connErrorMap 里
			loggo.Error("Error listening for tcp packets: %s %s", id, err.Error())
			p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src)
			p.addConnError(addr)
			return nil
		}
		// 拿到 tcp 连接
		targetConn := c.(*net.TCPConn)
		// 拿到 tcp 连接地址对象
		ipaddrTarget := targetConn.RemoteAddr().(*net.TCPAddr)

		// 帧管理器？
		fm := frame.NewFrameMgr(FRAME_MAX_SIZE, FRAME_MAX_ID, (int)(packet.my.TcpmodeBuffersize), (int)(packet.my.TcpmodeMaxwin), (int)(packet.my.TcpmodeResendTimems), (int)(packet.my.TcpmodeCompress),
			(int)(packet.my.TcpmodeStat))

		localConn := &ServerConn{exit: false, timeout: (int)(packet.my.Timeout), tcpconn: targetConn, tcpaddrTarget: ipaddrTarget, id: id, activeRecvTime: now, activeSendTime: now, close: false,
			rproto: (int)(packet.my.Rproto), fm: fm, tcpmode: (int)(packet.my.Tcpmode)}

		// 连接创建完毕，添加到 map 里
		p.addServerConn(id, localConn)

		// 启动转发协程，其中会把转为 tcp 包的数据发给实际目的服务器
		go p.RecvTCP(localConn, id, packet.src)
		return localConn

	} else {

		c, err := net.DialTimeout("udp", addr, time.Millisecond*time.Duration(p.connectTimeout))
		if err != nil {
			loggo.Error("Error listening for udp packets: %s %s", id, err.Error())
			p.remoteError(packet.echoId, packet.echoSeq, id, (int)(packet.my.Rproto), packet.src)
			p.addConnError(addr)
			return nil
		}
		targetConn := c.(*net.UDPConn)
		ipaddrTarget := targetConn.RemoteAddr().(*net.UDPAddr)

		localConn := &ServerConn{exit: false, timeout: (int)(packet.my.Timeout), conn: targetConn, ipaddrTarget: ipaddrTarget, id: id, activeRecvTime: now, activeSendTime: now, close: false,
			rproto: (int)(packet.my.Rproto), tcpmode: (int)(packet.my.Tcpmode)}

		p.addServerConn(id, localConn)

		go p.Recv(localConn, id, packet.src)

		return localConn
	}

	return nil
}

// processDataPacket 处理经过 icmp 解包后的数据
func (p *Server) processDataPacket(packet *Packet) {

	loggo.Debug("processPacket %s %s %d", packet.my.Id, packet.src.String(), len(packet.my.Data))

	// 每个 id 对应一个连接
	id := packet.my.Id
	localConn := p.getServerConnById(id)
	if localConn == nil {
		// id 没有对应的连接，要创建新的连接
		localConn = p.processDataPacketNewConn(id, packet)
		if localConn == nil {
			return
		}
	}

	now := common.GetNowUpdateInSecond()
	localConn.activeRecvTime = now
	localConn.echoId = packet.echoId
	localConn.echoSeq = packet.echoSeq

	if packet.my.Type == (int32)(MyMsg_DATA) {

		if packet.my.Tcpmode > 0 {
			// 转发 tcp 流量

			f := &frame.Frame{}
			err := proto.Unmarshal(packet.my.Data, f)
			// tcp protobuf 反序列化失败就关连接
			if err != nil {
				loggo.Error("Unmarshal tcp Error %s", err)
				return
			}

			localConn.fm.OnRecvFrame(f)
		} else {
			// 转发 udp 流量

			if packet.my.Data == nil {
				return
			}
			_, err := localConn.conn.Write(packet.my.Data)
			// udp 写失败就关连接
			if err != nil {
				loggo.Info("WriteToUDP Error %s", err)
				localConn.close = true
				return
			}
		}

		p.recvPacket++
		p.recvPacketSize += (uint64)(len(packet.my.Data))
	}
}

func (p *Server) RecvTCP(conn *ServerConn, id string, src *net.IPAddr) {

	defer common.CrashLog()

	p.workResultLock.Add(1)
	defer p.workResultLock.Done()

	loggo.Info("server waiting target response %s -> %s %s", conn.tcpaddrTarget.String(), conn.id, conn.tcpconn.LocalAddr().String())

	loggo.Info("start wait remote connect tcp %s %s", conn.id, conn.tcpaddrTarget.String())
	startConnectTime := common.GetNowUpdateInSecond()
	// 有没有建立好连接，没有的话就创建连接，然后把待发送的数据发出去
	for !p.exit && !conn.exit {
		// 什么情况下算建立好了？
		// frame 包里有专门的地方在做 connect 值的切换
		// 但是初始化的时候并不是 connected
		if conn.fm.IsConnected() {
			break
		}
		// 实际上 update 里就会设置 isConnected
		conn.fm.Update()
		/*
			func (fm *FrameMgr) GetSendList() *list.List {
				fm.sendlock.Lock()
				defer fm.sendlock.Unlock()
				ret := list.New()
				for e := fm.sendlist.Front(); e != nil; e = e.Next() {
					f := e.Value.(*Frame)
					ret.PushBack(f)
				}
				fm.sendlist.Init()
				return ret
			}
		*/
		// 将 sendlist 里的 frame pop 出来
		sendlist := conn.fm.GetSendList()
		for e := sendlist.Front(); e != nil; e = e.Next() {
			f := e.Value.(*frame.Frame)
			mb, _ := conn.fm.MarshalFrame(f)
			sendICMP(conn.echoId, conn.echoSeq, *p.conn, src, "", id, (uint32)(MyMsg_DATA), mb,
				conn.rproto, -1, p.key,
				0, 0, 0, 0, 0, 0,
				0)
			p.sendPacket++
			p.sendPacketSize += (uint64)(len(mb))
		}
		time.Sleep(time.Millisecond * 10)
		// 发送的超时控制，如果超时了，直接关闭连接，返回异常的 icmp 响应
		now := common.GetNowUpdateInSecond()
		diffclose := now.Sub(startConnectTime)
		if diffclose > time.Second*5 {
			loggo.Info("can not connect remote tcp %s %s", conn.id, conn.tcpaddrTarget.String())
			p.close(conn)
			p.remoteError(conn.echoId, conn.echoSeq, id, conn.rproto, src)
			return
		}
	}

	if !conn.exit {
		loggo.Info("remote connected tcp %s %s", conn.id, conn.tcpaddrTarget.String())
	}

	bytes := make([]byte, 10240)

	tcpActiveRecvTime := common.GetNowUpdateInSecond()
	tcpActiveSendTime := common.GetNowUpdateInSecond()

	// 不停的读取收到的数据
	for !p.exit && !conn.exit {
		now := common.GetNowUpdateInSecond()
		sleep := true

		left := common.MinOfInt(conn.fm.GetSendBufferLeft(), len(bytes))
		// 每次读的量有个上限
		if left > 0 {
			conn.tcpconn.SetReadDeadline(time.Now().Add(time.Millisecond * 1))
			n, err := conn.tcpconn.Read(bytes[0:left])
			// 读取异常就关闭 frameMgr
			if err != nil {
				nerr, ok := err.(net.Error)
				if !ok || !nerr.Timeout() {
					loggo.Info("Error read tcp %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
					conn.fm.Close()
					break
				}
			}
			if n > 0 {
				sleep = false
				conn.fm.WriteSendBuffer(bytes[:n])
				tcpActiveRecvTime = now
			}
		}

		conn.fm.Update()

		sendlist := conn.fm.GetSendList()
		if sendlist.Len() > 0 {
			sleep = false
			conn.activeSendTime = now
			for e := sendlist.Front(); e != nil; e = e.Next() {
				f := e.Value.(*frame.Frame)
				mb, err := conn.fm.MarshalFrame(f)
				if err != nil {
					loggo.Error("Error tcp Marshal %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
					continue
				}
				sendICMP(conn.echoId, conn.echoSeq, *p.conn, src, "", id, (uint32)(MyMsg_DATA), mb,
					conn.rproto, -1, p.key,
					0, 0, 0, 0, 0, 0,
					0)
				p.sendPacket++
				p.sendPacketSize += (uint64)(len(mb))
			}
		}

		if conn.fm.GetRecvBufferSize() > 0 {
			sleep = false
			rr := conn.fm.GetRecvReadLineBuffer()
			conn.tcpconn.SetWriteDeadline(time.Now().Add(time.Millisecond * 1))
			n, err := conn.tcpconn.Write(rr)
			if err != nil {
				nerr, ok := err.(net.Error)
				if !ok || !nerr.Timeout() {
					loggo.Info("Error write tcp %s %s %s", conn.id, conn.tcpaddrTarget.String(), err)
					conn.fm.Close()
					break
				}
			}
			if n > 0 {
				conn.fm.SkipRecvBuffer(n)
				tcpActiveSendTime = now
			}
		}

		if sleep {
			time.Sleep(time.Millisecond * 10)
		}

		diffrecv := now.Sub(conn.activeRecvTime)
		diffsend := now.Sub(conn.activeSendTime)
		tcpdiffrecv := now.Sub(tcpActiveRecvTime)
		tcpdiffsend := now.Sub(tcpActiveSendTime)
		if diffrecv > time.Second*(time.Duration(conn.timeout)) || diffsend > time.Second*(time.Duration(conn.timeout)) ||
			(tcpdiffrecv > time.Second*(time.Duration(conn.timeout)) && tcpdiffsend > time.Second*(time.Duration(conn.timeout))) {
			loggo.Info("close inactive conn %s %s", conn.id, conn.tcpaddrTarget.String())
			conn.fm.Close()
			break
		}

		if conn.fm.IsRemoteClosed() {
			loggo.Info("closed by remote conn %s %s", conn.id, conn.tcpaddrTarget.String())
			conn.fm.Close()
			break
		}
	}

	conn.fm.Close()

	startCloseTime := common.GetNowUpdateInSecond()
	for !p.exit && !conn.exit {
		now := common.GetNowUpdateInSecond()

		conn.fm.Update()

		sendlist := conn.fm.GetSendList()
		for e := sendlist.Front(); e != nil; e = e.Next() {
			f := e.Value.(*frame.Frame)
			mb, _ := conn.fm.MarshalFrame(f)
			sendICMP(conn.echoId, conn.echoSeq, *p.conn, src, "", id, (uint32)(MyMsg_DATA), mb,
				conn.rproto, -1, p.key,
				0, 0, 0, 0, 0, 0,
				0)
			p.sendPacket++
			p.sendPacketSize += (uint64)(len(mb))
		}

		nodatarecv := true
		if conn.fm.GetRecvBufferSize() > 0 {
			rr := conn.fm.GetRecvReadLineBuffer()
			conn.tcpconn.SetWriteDeadline(time.Now().Add(time.Millisecond * 100))
			n, _ := conn.tcpconn.Write(rr)
			if n > 0 {
				conn.fm.SkipRecvBuffer(n)
				nodatarecv = false
			}
		}

		diffclose := now.Sub(startCloseTime)
		if diffclose > time.Second*60 {
			loggo.Info("close conn had timeout %s %s", conn.id, conn.tcpaddrTarget.String())
			break
		}

		remoteclosed := conn.fm.IsRemoteClosed()
		if remoteclosed && nodatarecv {
			loggo.Info("remote conn had closed %s %s", conn.id, conn.tcpaddrTarget.String())
			break
		}

		time.Sleep(time.Millisecond * 100)
	}

	time.Sleep(time.Second)

	loggo.Info("close tcp conn %s %s", conn.id, conn.tcpaddrTarget.String())
	p.close(conn)
}

func (p *Server) Recv(conn *ServerConn, id string, src *net.IPAddr) {

	defer common.CrashLog()

	p.workResultLock.Add(1)
	defer p.workResultLock.Done()

	loggo.Info("server waiting target response %s -> %s %s", conn.ipaddrTarget.String(), conn.id, conn.conn.LocalAddr().String())

	bytes := make([]byte, 2000)

	for !p.exit {

		conn.conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		n, _, err := conn.conn.ReadFromUDP(bytes)
		if err != nil {
			nerr, ok := err.(net.Error)
			if !ok || !nerr.Timeout() {
				loggo.Info("ReadFromUDP Error read udp %s", err)
				conn.close = true
				return
			}
		}

		now := common.GetNowUpdateInSecond()
		conn.activeSendTime = now

		sendICMP(conn.echoId, conn.echoSeq, *p.conn, src, "", id, (uint32)(MyMsg_DATA), bytes[:n],
			conn.rproto, -1, p.key,
			0, 0, 0, 0, 0, 0,
			0)

		p.sendPacket++
		p.sendPacketSize += (uint64)(n)
	}
}

// close 关闭连接
func (p *Server) close(conn *ServerConn) {
	if p.getServerConnById(conn.id) != nil {
		conn.exit = true
		if conn.conn != nil {
			conn.conn.Close()
		}
		if conn.tcpconn != nil {
			conn.tcpconn.Close()
		}
		p.deleteServerConn(conn.id)
	}
}

// checkTimeoutConn 把超过超时时间的连接关闭，tcpmode 大于 0 的时候不会关闭
func (p *Server) checkTimeoutConn() {

	tmp := make(map[string]*ServerConn)
	p.localConnMap.Range(func(key, value interface{}) bool {
		id := key.(string)
		serverConn := value.(*ServerConn)
		tmp[id] = serverConn
		return true
	})

	now := common.GetNowUpdateInSecond()
	for _, conn := range tmp {
		if conn.tcpmode > 0 {
			continue
		}
		diffrecv := now.Sub(conn.activeRecvTime)
		diffsend := now.Sub(conn.activeSendTime)
		if diffrecv > time.Second*(time.Duration(conn.timeout)) || diffsend > time.Second*(time.Duration(conn.timeout)) {
			conn.close = true
		}
	}

	for id, conn := range tmp {
		if conn.tcpmode > 0 {
			continue
		}
		if conn.close {
			loggo.Info("close inactive conn %s %s", id, conn.ipaddrTarget.String())
			p.close(conn)
		}
	}
}

// showNet 打印一些网络相关日志，包括每秒发送/接受了多少个包/多少kb的数据以及存在多少个连接。打印完毕后数据会重新计算
func (p *Server) showNet() {
	p.localConnMapSize = 0
	p.localConnMap.Range(func(key, value interface{}) bool {
		p.localConnMapSize++
		return true
	})
	loggo.Info("send %dPacket/s %dKB/s recv %dPacket/s %dKB/s %dConnections",
		p.sendPacket, p.sendPacketSize/1024, p.recvPacket, p.recvPacketSize/1024, p.localConnMapSize)
	p.sendPacket = 0
	p.recvPacket = 0
	p.sendPacketSize = 0
	p.recvPacketSize = 0
}

func (p *Server) addServerConn(uuid string, serverConn *ServerConn) {
	p.localConnMap.Store(uuid, serverConn)
}

func (p *Server) getServerConnById(uuid string) *ServerConn {
	ret, ok := p.localConnMap.Load(uuid)
	if !ok {
		return nil
	}
	return ret.(*ServerConn)
}

func (p *Server) deleteServerConn(uuid string) {
	p.localConnMap.Delete(uuid)
}

func (p *Server) remoteError(echoId int, echoSeq int, uuid string, rprpto int, src *net.IPAddr) {
	sendICMP(echoId, echoSeq, *p.conn, src, "", uuid, (uint32)(MyMsg_KICK), []byte{},
		rprpto, -1, p.key,
		0, 0, 0, 0, 0, 0,
		0)
}

func (p *Server) addConnError(addr string) {
	_, ok := p.connErrorMap.Load(addr)
	if !ok {
		now := common.GetNowUpdateInSecond()
		p.connErrorMap.Store(addr, now)
	}
}

func (p *Server) isConnError(addr string) bool {
	_, ok := p.connErrorMap.Load(addr)
	return ok
}

// updateConnError 将存在于异常连接 map 里超过 5 秒的连接删除，5 秒之后就认为可以重新尝试了
func (p *Server) updateConnError() {

	tmp := make(map[string]time.Time)
	p.connErrorMap.Range(func(key, value interface{}) bool {
		id := key.(string)
		t := value.(time.Time)
		tmp[id] = t
		return true
	})

	now := common.GetNowUpdateInSecond()
	for id, t := range tmp {
		diff := now.Sub(t)
		if diff > time.Second*5 {
			p.connErrorMap.Delete(id)
		}
	}
}
