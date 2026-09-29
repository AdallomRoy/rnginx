//! Mail session handler - ngx_mail_handler.c ported to async Rust
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use ngx_core::connection::Connection;
use ngx_core::log::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_error};

use crate::core::MailSrvConf;

/// Mail session - similar to ngx_mail_session_t
pub struct MailSession {
    pub connection: Rc<Connection>,
    pub main_conf: Vec<Option<Rc<dyn Any>>>,
    pub srv_conf: Vec<Option<Rc<dyn Any>>>,
    pub protocol: i32, // pop3, imap, or smtp
    pub buffer: RefCell<Vec<u8>>,
    pub args: RefCell<Vec<Vec<u8>>>,
    pub out: RefCell<Vec<u8>>,
    pub salt: RefCell<Vec<u8>>,
    pub user: RefCell<Vec<u8>>,
    pub passwd: RefCell<Vec<u8>>,
    pub login_attempt: RefCell<u32>,
    pub starttls: RefCell<bool>,
    pub auth_method: RefCell<Vec<u8>>,
    pub upstream: RefCell<Option<Rc<Connection>>>,
    pub proxy_buffer_size: RefCell<usize>,
}

impl MailSession {
    pub fn new(
        connection: Rc<Connection>,
        main_conf: Vec<Option<Rc<dyn Any>>>,
        srv_conf: Vec<Option<Rc<dyn Any>>>,
    ) -> Self {
        MailSession {
            connection,
            main_conf,
            srv_conf,
            protocol: 0,
            buffer: RefCell::new(Vec::new()),
            args: RefCell::new(Vec::new()),
            out: RefCell::new(Vec::new()),
            salt: RefCell::new(Vec::new()),
            user: RefCell::new(Vec::new()),
            passwd: RefCell::new(Vec::new()),
            login_attempt: RefCell::new(0),
            starttls: RefCell::new(false),
            auth_method: RefCell::new(Vec::new()),
            upstream: RefCell::new(None),
            proxy_buffer_size: RefCell::new(16384),
        }
    }
}

/// Mail connection listener - spawned for each accepted connection
pub fn init_connection(c: Rc<Connection>) {
    ngx_core::event::spawn(async move {
        connection_task(c).await;
    });
}

async fn connection_task(c: Rc<Connection>) {
    // Get the server configuration for this address:port
    let (_addr_conf, srv_conf) = match get_addr_conf(&c) {
        Some(conf) => conf,
        None => {
            c.close();
            return;
        }
    };

    // Create session
    let session = Rc::new(MailSession::new(
        c.clone(),
        vec![], // main_conf will be filled from addr_conf
        vec![], // srv_conf will be filled from addr_conf
    ));

    let session_any: Rc<dyn Any> = session.clone();
    *c.data.borrow_mut() = Some(session_any);

    c.log.set_action(Some("sending client greeting line"));

    // Send protocol-specific greeting and start command loop
    if init_session(&session, &srv_conf).await.is_err() {
        close_connection(&c);
        return;
    }

    // Command reading loop
    read_command_loop(&session).await;

    close_connection(&c);
}

fn get_addr_conf(
    c: &Rc<Connection>,
) -> Option<(String, MailSrvConf)> {
    // TODO: get actual addr_conf from listening socket
    // For now, create a default
    Some((
        "127.0.0.1".to_string(),
        MailSrvConf::default(),
    ))
}

async fn init_session(
    session: &Rc<MailSession>,
    srv_conf: &MailSrvConf,
) -> Result<(), ()> {
    // TODO: Protocol-specific initialization
    Ok(())
}

async fn read_command_loop(session: &Rc<MailSession>) {
    let timeout = 60000u64; // TODO: from srv_conf
    loop {
        let c = &session.connection;
        let mut buf = vec![0u8; 4096];

        match tokio::time::timeout(
            Duration::from_millis(timeout),
            c.recv(&mut buf),
        )
        .await
        {
            Err(_) => {
                ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
                break;
            }
            Ok(Err(_)) => break,
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                let mut b = session.buffer.borrow_mut();
                b.extend_from_slice(&buf[..n]);
                drop(b);

                // TODO: Parse command and dispatch
            }
        }
    }
}

fn close_connection(c: &Rc<Connection>) {
    ngx_log_error!(NGX_LOG_DEBUG, c.log, None, "close mail connection");
    c.close();
}

pub fn send(c: &Rc<Connection>, out: &[u8]) {
    let c = c.clone();
    let data = out.to_vec();
    ngx_core::event::spawn(async move {
        let _ = c.send(&data).await;
    });
}
