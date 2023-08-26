use crate::msg::{self, PlainNAS5GSMessage};


use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, thread};

use crossbeam::{channel::{Receiver, Sender, unbounded}, queue::SegQueue};
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
        while true {
            match  itti_msg_queue.1.recv() {
                Ok(msg) => {
                    match msg {
                        IttiMsg::PduSessionMgmtCreatePduSession(plainNAS5GSMessage) => {
                            self.pdu_sessions.push(PduSession::default(self.trx.clone()));
                            let a = &self.pdu_sessions[0];
                            println!("PduSessionMgmtCreatePduSession {}",plainNAS5GSMessage.data);
                            a.run(self.trx.clone());
                        },
                        IttiMsg::PduSessionMgmtModifiyPduSession(PlainNAS5GSMessage) => {
                            
                        },
                        IttiMsg::PduSessionMgmtDestoryPduSession(PlainNAS5GSMessage) => {

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
        let RUNNING = Arc::new(AtomicBool::new(true));
        let RUNNING1 = RUNNING.clone();
        let RUNNING2 = RUNNING.clone();
        let RUNNING3 = RUNNING.clone();
        thread::spawn(move || {
            loop {
                match trx.1.recv() {
                    Ok(i) => {
                        if i == 1 {
                            RUNNING1.store(false, Ordering::Relaxed);
                            println!("destoryed");

                        }
                    },
                    Err(_) => {
                        
                    },
                }
            }
        });
        thread::spawn(move || {
                while RUNNING2.load(Ordering::Relaxed) {
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