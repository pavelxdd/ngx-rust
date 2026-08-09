use core::ffi::c_int;
use core::mem;
use core::ptr;

use libc::sockaddr_storage;
use ngx::core::{NgxStr, Pool, SocketType, Status};
use ngx::ffi::{
    NGX_HTTP_MODULE, in_port_t, ngx_conf_t, ngx_http_module_t, ngx_inet_get_port, ngx_int_t,
    ngx_module_t, ngx_sock_ntop, ngx_str_t, sockaddr,
};
use ngx::http::{
    self, HttpModule, HttpModuleRequestContext, HttpVariableFlags, HttpVariableHandler,
    HttpVariableValue, add_variable,
};
use ngx::ngx_log_debug_http;

const IPV4_STRLEN: usize = b"255.255.255.255\0".len();

#[derive(Debug, Default)]
struct NgxHttpOrigDstCtx {
    orig_dst_addr: ngx_str_t,
    orig_dst_port: ngx_str_t,
}

impl NgxHttpOrigDstCtx {
    pub fn save(&mut self, addr: &str, port: in_port_t, pool: &Pool<'_>) -> Status {
        let Some(addr) = (unsafe { ngx_str_t::from_bytes(pool.as_ptr(), addr.as_bytes()) }) else {
            return Status::NGX_ERROR;
        };

        let port_str = port.to_string();
        let Some(port) = (unsafe { ngx_str_t::from_bytes(pool.as_ptr(), port_str.as_bytes()) })
        else {
            return Status::NGX_ERROR;
        };

        self.orig_dst_addr = addr;
        self.orig_dst_port = port;

        Status::NGX_OK
    }

    fn bind_addr(
        &self,
        request: &http::RequestRefMut<'_>,
        output: &mut HttpVariableValue<'_>,
    ) -> Status {
        Self::bind(self.orig_dst_addr, request, output)
    }

    fn bind_port(
        &self,
        request: &http::RequestRefMut<'_>,
        output: &mut HttpVariableValue<'_>,
    ) -> Status {
        Self::bind(self.orig_dst_port, request, output)
    }

    fn bind(
        value: ngx_str_t,
        request: &http::RequestRefMut<'_>,
        output: &mut HttpVariableValue<'_>,
    ) -> Status {
        if value.len == 0 {
            output.set_not_found();
            return Status::NGX_OK;
        }

        let value = unsafe { NgxStr::from_ngx_str(value) };
        output
            .copy_from_request(request, value.as_bytes())
            .map(|()| Status::NGX_OK)
            .unwrap_or(Status::NGX_ERROR)
    }
}

static NGX_HTTP_ORIG_DST_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(http::preconfiguration::<Module>),
    postconfiguration: Some(http::postconfiguration::<Module>),
    create_main_conf: None,
    init_main_conf: None,
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: None,
    merge_loc_conf: None,
};

// Generate the `ngx_modules` table with exported modules.
// This feature is required to build a 'cdylib' dynamic module outside of the NGINX buildsystem.
#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_orig_dst_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), unsafe(no_mangle))]
pub static mut ngx_http_orig_dst_module: ngx_module_t = ngx_module_t {
    ctx: &raw const NGX_HTTP_ORIG_DST_MODULE_CTX as _,
    commands: ptr::null_mut(),
    type_: NGX_HTTP_MODULE as _,
    ..ngx_module_t::default()
};

fn ngx_get_origdst(request: &mut http::RequestRefMut<'_>) -> Result<(String, in_port_t), Status> {
    {
        let mut connection = request.connection_mut().map_err(|_| Status::NGX_ERROR)?;
        if !matches!(connection.socket_type(), Ok(SocketType::Stream)) {
            ngx_log_debug_http!(request, "httporigdst: connection is not type SOCK_STREAM");
            return Err(Status::NGX_DECLINED);
        }
        if connection.refresh_local_address().is_err() {
            ngx_log_debug_http!(request, "httporigdst: no local sockaddr from connection");
            return Err(Status::NGX_ERROR);
        }
    }

    let c = unsafe { (*request.as_ptr()).connection };

    let level: c_int;
    let optname: c_int;
    match unsafe { (*(*c).local_sockaddr).sa_family } as i32 {
        libc::AF_INET => {
            level = libc::SOL_IP;
            optname = libc::SO_ORIGINAL_DST;
        }
        _ => {
            ngx_log_debug_http!(request, "httporigdst: only support IPv4");
            return Err(Status::NGX_DECLINED);
        }
    }

    let mut addr: sockaddr_storage = unsafe { mem::zeroed() };
    let mut addrlen: libc::socklen_t = mem::size_of_val(&addr) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt((*c).fd, level, optname, (&raw mut addr).cast(), &raw mut addrlen)
    };
    if rc == -1 {
        ngx_log_debug_http!(request, "httporigdst: getsockopt failed");
        return Err(Status::NGX_DECLINED);
    }
    let mut ip: Vec<u8> = vec![0; IPV4_STRLEN];
    let e = unsafe {
        ngx_sock_ntop(
            (&raw mut addr).cast(),
            mem::size_of::<sockaddr>() as u32,
            ip.as_mut_ptr(),
            IPV4_STRLEN,
            0,
        )
    };
    if e == 0 {
        ngx_log_debug_http!(request, "httporigdst: ngx_sock_ntop failed to convert sockaddr");
        return Err(Status::NGX_ERROR);
    }
    ip.truncate(e);

    let port = unsafe { ngx_inet_get_port((&raw mut addr).cast()) };

    Ok((String::from_utf8(ip).unwrap(), port))
}

struct OrigDstAddrVariable;

impl HttpVariableHandler for OrigDstAddrVariable {
    type Output = Status;

    fn get(
        request: &mut http::RequestRefMut<'_>,
        value: &mut HttpVariableValue<'_>,
        _: usize,
    ) -> Self::Output {
        let ctx = match request.module_context::<Module>() {
            Ok(ctx) => ctx,
            Err(_) => return Status::NGX_ERROR,
        };
        if let Some(obj) = ctx {
            ngx_log_debug_http!(request, "httporigdst: found context and binding variable",);
            return obj.bind_addr(request, value);
        }
        // lazy initialization:
        //   get original dest information
        //   create context
        //   set context
        // bind address
        ngx_log_debug_http!(request, "httporigdst: context not found, getting address");
        let r = ngx_get_origdst(request);
        match r {
            Err(e) => {
                return e;
            }
            Ok((ip, port)) => {
                // create context,
                // set context
                ngx_log_debug_http!(request, "httporigdst: saving ip - {:?}, port - {}", ip, port,);
                let raw_pool = match request.pool() {
                    Ok(pool) => pool.as_ptr(),
                    Err(_) => return Status::NGX_ERROR,
                };
                let address = {
                    let Ok(new_ctx) = request
                        .get_or_insert_module_context_with::<Module>(NgxHttpOrigDstCtx::default)
                    else {
                        return Status::NGX_ERROR;
                    };
                    // SAFETY: the request and its pool remain live for this variable callback.
                    let status =
                        unsafe { Pool::with_raw(raw_pool, |pool| new_ctx.save(&ip, port, &pool)) }
                            .unwrap_or(Status::NGX_ERROR);
                    if let Err(status) = status.into_result() {
                        return status;
                    }
                    new_ctx.orig_dst_addr
                };
                return NgxHttpOrigDstCtx::bind(address, request, value);
            }
        }
    }
}

struct OrigDstPortVariable;

impl HttpVariableHandler for OrigDstPortVariable {
    type Output = Status;

    fn get(
        request: &mut http::RequestRefMut<'_>,
        value: &mut HttpVariableValue<'_>,
        _: usize,
    ) -> Self::Output {
        let ctx = match request.module_context::<Module>() {
            Ok(ctx) => ctx,
            Err(_) => return Status::NGX_ERROR,
        };
        if let Some(obj) = ctx {
            ngx_log_debug_http!(request, "httporigdst: found context and binding variable",);
            return obj.bind_port(request, value);
        }
        // lazy initialization:
        //   get original dest information
        //   create context
        //   set context
        // bind port
        ngx_log_debug_http!(request, "httporigdst: context not found, getting address");
        let r = ngx_get_origdst(request);
        match r {
            Err(e) => {
                return e;
            }
            Ok((ip, port)) => {
                // create context,
                // set context
                ngx_log_debug_http!(request, "httporigdst: saving ip - {:?}, port - {}", ip, port,);
                let raw_pool = match request.pool() {
                    Ok(pool) => pool.as_ptr(),
                    Err(_) => return Status::NGX_ERROR,
                };
                let port = {
                    let Ok(new_ctx) = request
                        .get_or_insert_module_context_with::<Module>(NgxHttpOrigDstCtx::default)
                    else {
                        return Status::NGX_ERROR;
                    };
                    // SAFETY: the request and its pool remain live for this variable callback.
                    let status =
                        unsafe { Pool::with_raw(raw_pool, |pool| new_ctx.save(&ip, port, &pool)) }
                            .unwrap_or(Status::NGX_ERROR);
                    if let Err(status) = status.into_result() {
                        return status;
                    }
                    new_ctx.orig_dst_port
                };
                return NgxHttpOrigDstCtx::bind(port, request, value);
            }
        }
    }
}

struct Module;

unsafe impl HttpModule for Module {
    fn module() -> &'static ngx_module_t {
        unsafe { &*::core::ptr::addr_of!(ngx_http_orig_dst_module) }
    }

    fn preconfigure(cf: &mut ngx_conf_t) -> ngx_int_t {
        if add_variable::<OrigDstAddrVariable>(
            cf,
            NgxStr::from_bytes(b"server_orig_addr"),
            HttpVariableFlags::empty(),
            0,
        )
        .is_err()
        {
            return Status::NGX_ERROR.0;
        }
        if add_variable::<OrigDstPortVariable>(
            cf,
            NgxStr::from_bytes(b"server_orig_port"),
            HttpVariableFlags::empty(),
            0,
        )
        .is_err()
        {
            return Status::NGX_ERROR.0;
        }
        Status::NGX_OK.0
    }
}

unsafe impl HttpModuleRequestContext for Module {
    type RequestContext = NgxHttpOrigDstCtx;
}
