use crate::msg;


use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, thread};

use crossbeam::channel::{Receiver, Sender, unbounded};
use msg::IttiMsg;


pub struct  PduSessionMgmt {
    pub pdu_sessions: Vec<PduSession>,
    pub trx: (Sender<i32>,Receiver<i32>)
}

impl PduSessionMgmt {
    pub fn default() -> PduSessionMgmt {
        PduSessionMgmt { 
            pdu_sessions: vec![],
            trx: unbounded()
         }
    }

    pub fn init_pdu_session_mgmt_task(mut self,itti_msg_queue: (Sender<IttiMsg>,Receiver<IttiMsg>)) {
        loop {
            match  itti_msg_queue.1.recv() {
                Ok(msg) => {
                    match msg {
                        IttiMsg::PduSessionMgmtCreatePduSession(plain_nas5_gsmessage) => {
                            self.pdu_sessions.push(PduSession::default(self.trx.clone()));
                            let a = &self.pdu_sessions[0];
                            println!("PduSessionMgmtCreatePduSession {}",plain_nas5_gsmessage.data);
                            a.run(self.trx.clone());
                        },
                        IttiMsg::PduSessionMgmtModifiyPduSession(plain_nas5_gsmessage) => {
                            
                        },
                        IttiMsg::PduSessionMgmtDestoryPduSession(plain_nas5_gsmessage) => {

                            self.pdu_sessions.push(PduSession::default(self.trx.clone()));
                        let a = &self.pdu_sessions[0];
                        a.destory(self.trx.clone());
                        drop(a);
                        },
                        _ => {println!("{:#?}", msg);},
                    }
                },
                Err(_) => {
                    
                },
            }
            
        }
    }
}

pub struct  PduSession {
    pub pdu_id: i32,
    pub qos_rules: i32,
    pub trx: (Sender<i32>,Receiver<i32>)
}


impl PduSession {
    pub fn default(trx: (Sender<i32>,Receiver<i32>)) -> PduSession {
        PduSession {
            pdu_id: 1,
            qos_rules: 1,
            trx : trx.clone()
        }
    }
    
    pub fn run(&self, trx: (Sender<i32>,Receiver<i32>)) {
        let running = Arc::new(AtomicBool::new(true));
        let running1 = running.clone();
        let running2 = running.clone();
        let _running3 = running.clone();
        thread::spawn(move || {
            loop {
                match trx.1.recv() {
                    Ok(i) => {
                        if i == 1 {
                            running1.store(false, Ordering::Relaxed);
                            println!("destoryed");

                        }
                    },
                    Err(_) => {
                        
                    },
                }
            }
        });
        thread::spawn(move || {
                while running2.load(Ordering::Relaxed) {
                    // println!("{:#?}",RUNNING2);
                }
                println!("destoryed");
            });
        // thread::spawn(move || {
        //         while RUNNING3.load(Ordering::Relaxed) {
        //             // println!("{}",running_flag);
        //         }
        //         println!("destoryed");
        //     });
        
    }

    pub fn destory(&self, trx: (Sender<i32>,Receiver<i32>)) {
        trx.0.send(1);
    }

}