use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{thread, default};
use std::time::Duration;
use crossbeam::channel::{select, unbounded, Receiver ,Sender};
use crossbeam::queue::{SegQueue, ArrayQueue};
use crossbeam::scope;

struct  PduSessionMgmt {
    pdu_sessions: Vec<PduSession>,
    trx: (Sender<i32>,Receiver<i32>)
}

impl PduSessionMgmt {
    pub fn default() -> PduSessionMgmt {
        PduSessionMgmt { 
            pdu_sessions: vec![],
            trx: unbounded()
         }
    }
    pub fn init_pdu_session_mgmt_task(mut self,itti_msg_queue: Arc<SegQueue<i32>>,) {
        while true {

            match  itti_msg_queue.pop() {
                Some(msg) => {
                    if msg == 1 {
                        self.pdu_sessions.push(PduSession::default(self.trx.clone()));
                        let a = &self.pdu_sessions[0];
                        a.run(self.trx.clone());
                    }
                    else if msg == 2 {
                        self.pdu_sessions.push(PduSession::default(self.trx.clone()));
                        let a = &self.pdu_sessions[0];
                        a.destory(self.trx.clone());
                        drop(a);
                    }
                    else {
                        println!("{}", msg);
                    }
                },
                None => {
                    
                },
            }
            
        }
    }
}

struct  PduSession {
    pdu_id: i32,
    qos_rules: i32,
    trx: (Sender<i32>,Receiver<i32>)
}


impl PduSession {
    pub fn default(trx: (Sender<i32>,Receiver<i32>)) -> PduSession {
        PduSession {
            pdu_id: 1,
            qos_rules: 1,
            trx : trx
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
                    // println!("{}",running_flag);
                }
                println!("destoryed");
            });
        thread::spawn(move || {
                while RUNNING3.load(Ordering::Relaxed) {
                    // println!("{}",running_flag);
                }
                println!("destoryed");
            });
        
    }

    pub fn destory(&self, trx: (Sender<i32>,Receiver<i32>)) {
        trx.0.send(1);
    }

}

fn main() {
    let global_task_queue = Arc::new(SegQueue::<i32>::new());
    let global_task_queue_pdu = global_task_queue.clone();
    scope(|scope| {
        //     scope.spawn(|_| {
        //         let mut i: i32=1;
        //         while true {
        //             global_task_queue.push(i);
        //             i += 1;
        // }
        //     });
        // let (tx,rx)= unbounded::<i32>();
        // let mut pduSession = PduSession::default((tx.clone(),rx.clone()));
        // let mut pduSession1 = PduSession::default((tx.clone(),rx.clone()));

        // pduSession.run(pduSession.trx.clone());
        // pduSession1.run(pduSession.trx.clone());
        // pduSession.destory(pduSession.trx.clone());
        // // pduSession1.destory(pduSession.trx.clone());
       
            scope.spawn(move |_|{
                let mut pduSessionMgmt = PduSessionMgmt::default();
                pduSessionMgmt.init_pdu_session_mgmt_task(global_task_queue_pdu);
                // while true {
                //     match global_task_queue.pop() {
                //         Some(int) => {
                //             if int %2 == 0 {
                //                 println!("even {:#?}",int);
                //             }
                //             else {
                //                 global_task_queue.push(int);
                //             }
                //         },
                //         None => todo!(),
                //     }
                // }
            });
            global_task_queue.push(1);
            global_task_queue.push(3);
            global_task_queue.push(2);


            scope.spawn(move |_|{
                // while true {

                    // match global_task_queue.pop() {
                    //     Some(int) => {
                    //         if int %2 != 0 {
                    //             // println!("odd {:#?}",int);
                    //         }
                    //         else {
                    //             global_task_queue.push(int);
                    //         }
                    //     },
                    //     None => todo!(),
                    // }
                // }
            });

            loop {
                // if global_task_queue.pop().is_none() {
                //     thread::yield_now();
                // } else {
                //     break;
                // }
            }
    })
    .unwrap();
 

    
    // At most one of these two receive operations will be executed.
    // select! {
    //     recv(r1) -> msg => assert_eq!(msg, Ok(10)),
    //     recv(r2) -> msg => assert_eq!(msg, Ok(20)),
    //     default(Duration::from_secs(1)) => println!("timed out"),
    // }
}