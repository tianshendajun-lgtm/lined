import Foundation
import Network

/*
 * 方案 B：替换 LINE 的 GOT 槽 NWConnection.init(to:using:)。
 *
 * 只改 LINE 自己镜像里的数据指针（__got/__la_symbol_ptr），
 * 不写任何 __TEXT（系统库或 LINE），iOS 26 不触发 CSM 崩。
 *
 * 替身把 legy/uts 的 endpoint 改成 127.0.0.1:relay，
 * 真实目标登记进 C 侧中继队列（la_pending_push_c），
 * 再调 NWConnection(to:using:)（走本 dylib 自己的未改导入 = 真 init，不递归）。
 *
 * C 接口见 LineProxyHook-Bridging.h（-import-objc-header）。
 */

private func laHookedInit(_ endpoint: __owned NWEndpoint,
                          _ parameters: NWParameters) -> NWConnection {
    if !la_proxy_off_c(),
       case let NWEndpoint.hostPort(host, port) = endpoint {
        let hostStr = String(describing: host)
        let shouldRelay = hostStr.withCString { la_host_should_relay_c($0) }
        let rport = la_relay_port_c()
        if shouldRelay, rport != 0 {
            let slot = la_current_slot_c()
            _ = hostStr.withCString { la_pending_push_c($0, port.rawValue, slot) }
            if let lp = NWEndpoint.Port(rawValue: rport) {
                let local = NWEndpoint.hostPort(host: "127.0.0.1", port: lp)
                return NWConnection(to: local, using: parameters)
            }
        }
    }
    // 非目标 / 未就绪：原样建连
    return NWConnection(to: endpoint, using: parameters)
}

// 返回替身函数指针给 C（Tweak.m 用 rebind_symbols 写进 LINE 的 GOT）。
// laHookedInit 是全局函数 = @convention(thin)，ABI 与 init 的方法约定兼容：
// 方法约定把 self(元类型) 放 x20，普通参数 x0(endpoint 指针)/x1(parameters) 对齐，
// thin 替身不读 x20，忽略即可。
@_cdecl("la_get_nwconn_hook")
public func la_get_nwconn_hook() -> UnsafeMutableRawPointer {
    let f: @convention(thin) (__owned NWEndpoint, NWParameters) -> NWConnection = laHookedInit
    return unsafeBitCast(f, to: UnsafeMutableRawPointer.self)
}
