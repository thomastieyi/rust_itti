
use serde_json::{self, Value};
#[derive(PartialEq, Eq, Hash)]
pub enum IttiTrxTag {
    PduSessionMgmt,
    NasDecoer,
    Listener,
    GtpUdp
}

#[derive(Debug,Clone)]
pub enum IttiMsg  {

    //PduSessionMgmt Msg
    PduSessionMgmtCreatePduSession(PlainNAS5GSMessage),
    PduSessionMgmtModifiyPduSession(PlainNAS5GSMessage),
    PduSessionMgmtDestoryPduSession(PlainNAS5GSMessage),
    PduSessionMgmtStopThread,

    //NAS-5GS decoder Msg
    Nas5GsDecodePduAndSend2PduMgmt(NasDecoerSdu),
    Nas5GsStopThread,

    //Incoming server listener Msg
    ListenerInitAndRun,
    ListenerDestory,
    ListenerStopThread,

    //GTP-U UDP TRX Msg
    GtpUdpCfgSetup,
    GtpUdpSendToRemote(UdpGtpBuffer), 
    GtpUdpRecvFromRemoteThenToPduSessoin(UdpGtpBuffer),
    GtpUdpStopThread,

}
#[derive(Debug,Clone)]

pub struct NasDecoerSdu{
    pub sdu:Vec<u8>
}
#[derive(Debug,Clone)]

pub struct PlainNAS5GSMessage {
    pub data:Value
}

#[derive(Debug,Clone)]

pub struct UdpGtpBuffer {
    pub data:Value
}
