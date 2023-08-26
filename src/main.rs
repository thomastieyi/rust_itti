
mod msg;
mod pdu_session;
mod nas_decoder;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use crossbeam::channel::{unbounded, Receiver ,Sender};
use crossbeam::queue::SegQueue;
use crossbeam::scope;
use msg::{IttiMsg, IttiTrxTag, PlainNAS5GSMessage, NasDecoerSdu};
use nas_decoder::nas_5gs_decoder;
use pdu_session::PduSessionMgmt;


fn main() {
    let global_task_queue = Arc::new(SegQueue::<IttiMsg>::new());
    let global_itti_trx_tag_list = Arc::new(RwLock::new(HashMap::<IttiTrxTag,(Sender<IttiMsg>,Receiver<IttiMsg>)>::new()));
    let global_itti_trx_tag_list_pdu = global_itti_trx_tag_list.clone();
    let global_itti_trx_tag_list_nas_decoder = global_itti_trx_tag_list.clone();
    let global_task_queue_handler = global_task_queue.clone();
    let global_itti_trx_tag_list_handler = global_itti_trx_tag_list.clone();
    scope(|scope| {

            scope.spawn(move |_|{
                //Thread for nas decoder
                let nas_decoder_trx: (Sender<IttiMsg>, Receiver<IttiMsg>) = unbounded::<IttiMsg>();
                // global_itti_trx_tag_list_pdu.insert(IttiTrxTag::NasDecoer, nas_decoder_trx.clone()); // 插入
                {
                    loop {
                        let bb = global_itti_trx_tag_list_pdu.try_write();

                        match bb {
                            Ok(mut b) => {
                                println!("a");
                                b.insert(IttiTrxTag::NasDecoer, nas_decoder_trx.clone()); 
                                // global_itti_trx_tag_list_pdu.
                                break;
                            },
                            Err(_) => {
                                continue;
                            },
                        }
                    }
                }
                loop {
                    match  nas_decoder_trx.1.recv() {
                        Ok(msg) => {
                            match msg {
                                IttiMsg::Nas5GsDecodePduAndSend2PduMgmt(data_to_decode) => {
                                    if let Ok(plain_nas5_gsmessage) = nas_5gs_decoder(data_to_decode.sdu) {
                                        println!("{:#?}", plain_nas5_gsmessage);
                                        let bb = global_itti_trx_tag_list_pdu.try_read().unwrap();
                                        if bb.contains_key(&IttiTrxTag::PduSessionMgmt) {
                                            match  bb.get(&IttiTrxTag::PduSessionMgmt){
                                                Some(pdu_trx) =>{
                                                    let _ = pdu_trx.0.send(IttiMsg::PduSessionMgmtCreatePduSession(PlainNAS5GSMessage { data: plain_nas5_gsmessage.clone() }));
                                                },
                                                None => {
                
                                                },
                                            } {
            
                                            } 
                                        }


                                    }
                                },
                                IttiMsg::Nas5GsStopThread => {
                                    break;
                                },
                                _ => {},
                            }
                        },
                        Err(_) => {
                            
                        },
                    }
                    
                }
            });
            
            scope.spawn(move |_|{
                //Thread pduSessionMgmt
                let pdu_session_mgmt = PduSessionMgmt::default();
                let pdu_trx = unbounded::<IttiMsg>();
                
                {
                loop {
                    let b = global_itti_trx_tag_list_nas_decoder.try_write();
                    match b {
                        Ok(mut b) => {
                            b.insert(IttiTrxTag::PduSessionMgmt, pdu_trx.clone());
                            println!("b");
                            break;
                        },
                        Err(_) => {
                            continue;
                        },
                    }
                }
            }
                pdu_session_mgmt.init_pdu_session_mgmt_task(pdu_trx.clone());
            });

            scope.spawn(move |_|{
                //Thread Itti
                match  global_task_queue_handler.pop() {
                    Some(msg) => {
                        match msg{
                            IttiMsg::PduSessionMgmtCreatePduSession(plain_nas5_gsmessage) |
                            IttiMsg::PduSessionMgmtModifiyPduSession(plain_nas5_gsmessage)|
                            IttiMsg::PduSessionMgmtDestoryPduSession(plain_nas5_gsmessage)
                                  => {
                                        loop{
                                            let global_itti_trx_tag_list_handler = global_itti_trx_tag_list_handler.try_read();
                                            match global_itti_trx_tag_list_handler {
                                                Ok(g) => {
                                                    if g.contains_key(&IttiTrxTag::PduSessionMgmt) {
                                                        let pdu_trx =  g.get(&IttiTrxTag::PduSessionMgmt);
                                                        match pdu_trx {
                                                            Some(pdu_trx) => {
                                                                let _ = pdu_trx.0.send(IttiMsg::PduSessionMgmtCreatePduSession(plain_nas5_gsmessage.clone()));
                                                                println!("PduSessionMgmt");
                                                            },
                                                            None => {
                                                            },
                                                        }
                                                    }
                                                    break;
                                                },
                                                Err(_) => {
                                                    continue;
                                                },
                                            }
                                            
                                        }
                                        
                                    },
                            IttiMsg::Nas5GsDecodePduAndSend2PduMgmt(nas_decoer_sdu) =>{
                                        loop{
                                            let global_itti_trx_tag_list_handler = global_itti_trx_tag_list_handler.try_read();
                                            match global_itti_trx_tag_list_handler {
                                                Ok(g) => {
                                                    if g.contains_key(&IttiTrxTag::NasDecoer) {
                                                        let pdu_trx =  g.get(&IttiTrxTag::NasDecoer);
                                                        match pdu_trx {
                                                            Some(pdu_trx) => {
                                                                let _ = pdu_trx.0.send(IttiMsg::Nas5GsDecodePduAndSend2PduMgmt(nas_decoer_sdu.clone()));
                                                                println!("nasDecoerSdu");
                                                            },
                                                            None => {
                                                            },
                                                        }
                                                    }
                                                    break;
                                                },
                                                Err(_) => {
                                                    continue;
                                                },
                                            }
                                            
                                        }
                            }
                            _ => {println!("{:#?}", msg);},
                        }
                    },
                    None => {
                        
                    },
                }
            });
            
            
            // global_task_queue.push(1);
            // global_task_queue.push(3);
            // global_task_queue.push(2);
            let nas_test_msg = IttiMsg::Nas5GsDecodePduAndSend2PduMgmt(NasDecoerSdu { sdu: vec![0x7e,0x00,0x68,0x01,0x00,0x65,0x2e,0x01,0x01,0xc2,0x11,0x00,0x09,0x01,0x00,0x06,0x31,0x3f,0x01,0x01,0xff,0x01,0x06,0x06,0x13,0x88,0x04,0x7a,0x12,0x59,0x32,0x29,0x05,0x01,0xac,0x1a,0x64,0x65,0x22,0x01,0x01,0x79,0x00,0x06,0x01,0x20,0x41,0x01,0x01,0x09,0x7b,0x00,0x18,0x80,0x80,0x21,0x0a,0x03,0x00,0x00,0x0a,0x81,0x06,0x08,0x08,0x08,0x08,0x00,0x0d,0x04,0x08,0x08,0x08,0x08,0x00,0x11,0x00,0x25,0x1c,0x09,0x69,0x69,0x6e,0x74,0x65,0x72,0x6e,0x65,0x74,0x06,0x6d,0x6e,0x63,0x30,0x30,0x31,0x06,0x6d,0x63,0x63,0x30,0x30,0x31,0x04,0x67,0x70,0x72,0x73,0x12,0x01] });
            global_task_queue.push(nas_test_msg);

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