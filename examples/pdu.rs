use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// 参数容器
#[derive(Debug, Clone)]
struct ParamContainer {
    _container_id: u16,
    _container_len: u8,
    _container_content: Vec<u8>,
}

#[derive(Debug)]
pub struct ExtProtoCfgOpts {
    _length: u16,
    //   config_proto: u8,
    _pco_units: Vec<ParamContainer>,
}

impl Default for ParamContainer {
    fn default() -> Self {
        Self {
            _container_id: 0,
            _container_len: 0,
            _container_content: Vec::new(),
        }
    }
}

impl Default for ExtProtoCfgOpts {
    fn default() -> Self {
        Self {
            _length: 0,
            _pco_units: Vec::new(),
        }
    }
}

impl ParamContainer {
    pub fn to_ipv6_addr(&mut self) -> Option<Ipv6Addr> {
        if self._container_len == 16 {
            // 8 * 16 = 128 bit ipv6
            let array: [u8; 16] = self._container_content.as_slice().try_into().unwrap();
            Some(Ipv6Addr::from(array));
        }
        None
    }
}

impl ExtProtoCfgOpts {
    pub fn get_pcscf_v6_addr(&mut self) -> Option<Ipv6Addr> {
        let pco_units = self._pco_units.clone();

        for mut param_container in pco_units {
            if param_container._container_id == 0x0001 {
                let array: [u8; 16] = param_container
                    ._container_content
                    .as_slice()
                    .try_into()
                    .unwrap();
                // debug!("pcscf {:#?}", array);
                // debug!("pcscf v6 {:#?}", Ipv6Addr::from(array));
                // Ipv6Addr::from(param_container._container_content);
                return Some(Ipv6Addr::from(array));
                // return None;
            }
        }
        return None;
    }

    pub fn get_dns_v6_addr(&mut self) -> Option<Ipv6Addr> {
        let pco_units = self._pco_units.clone();

        for mut param_container in pco_units {
            if param_container._container_id == 0x0003 {
                return param_container.to_ipv6_addr();
            }
        }
        None
    }
}

// 解析函数
pub fn parse_extended_pco(data: &[u8]) -> Option<ExtProtoCfgOpts> {
    let mut params = vec![];

    let mut _i = 3; // 前4字节是类型和长度
    let length = u16::from_be_bytes([data[1], data[2]]);
    // print!("{:#?}\n",length);
    let mut i = 4;
    // 解析附加参数列表
    while i < data.len() {
        let container_id = u16::from_be_bytes([data[i], data[i + 1]]);
        // print!("{:#?}\n",container_id);

        let container_len = data[i + 2];
        let container_content = &data[i + 3..i + 3 + container_len as usize];

        let container = ParamContainer {
            _container_id: container_id,
            _container_len: container_len,
            _container_content: container_content.to_vec(),
        };

        params.push(container);

        i += 3 + container_len as usize;
    }
    let ext: ExtProtoCfgOpts = ExtProtoCfgOpts {
        _length: length,
        _pco_units: params,
    };
    Some(ext)
    // 输出解析结果
}

// const PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_IEI: u8 = 0x59;
const _PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_IEI: u8 = 0x29;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_IEI: u8 = 0x56;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_IEI: u8 = 0x22;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_IEI: u8 = 0x80;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_IEI: u8 = 0x75;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_IEI: u8 = 0x78;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_IEI: u8 = 0x79;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_IEI: u8 = 0x7B;
const _PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_IEI: u8 = 0x25;

// const PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_PRESENCE: u16 = 1 << 0;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_PRESENCE: u16 = 1 << 1;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_PRESENCE: u16 = 1 << 2;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_PRESENCE: u16 = 1 << 3;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE: u16 = 1 << 4;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_PRESENCE: u16 = 1 << 5;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_PRESENCE: u16 = 1 << 6;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_PRESENCE: u16 = 1 << 7;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_PRESENCE: u16 = 1 << 8;
// const PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_PRESENCE: u16 = 1 << 9;
// use std::mem::ManuallyDrop;

use std::alloc::alloc;
use std::alloc::Layout;
use std::slice;

#[derive(Debug, PartialEq)]
pub enum SessionMessageType {
    Unknown,
    EstablishmentRequest,
    EstablishmentAccept,
    EstablishmentReject,
    AuthenticationCommand,
    AuthenticationComplete,
    AuthenticationResult,
    ModificationRequest,
    ModificationReject,
    ModificationCommand,
    ModificationComplete,
    ModificationCommandReject,
    ReleaseRequest,
    ReleaseReject,
    ReleaseCommand,
    ReleaseComplete,
}
#[derive(Debug, PartialEq)]
pub enum PduAddressType {
    IPV4,
    IPV6,
    IPV4V6,
    Unknown,
}

impl PduAddressType {
    pub fn from_u8(val: u8) -> PduAddressType {
        match val {
            0b00000001 => PduAddressType::IPV4,
            0b00000010 => PduAddressType::IPV6,
            0b00000011 => PduAddressType::IPV4V6,
            _ => PduAddressType::Unknown,
        }
    }
}

impl SessionMessageType {
    pub(crate) fn from_u8(val: u8) -> SessionMessageType {
        match val {
            0b00000001 => SessionMessageType::Unknown,
            0b11000001 => SessionMessageType::EstablishmentRequest,
            0b11000010 => SessionMessageType::EstablishmentAccept,
            0b11000011 => SessionMessageType::EstablishmentReject,

            0b11000101 => SessionMessageType::AuthenticationCommand,
            0b11000110 => SessionMessageType::AuthenticationComplete,
            0b11000111 => SessionMessageType::AuthenticationResult,

            0b11001001 => SessionMessageType::ModificationRequest,
            0b11001010 => SessionMessageType::ModificationReject,
            0b11001011 => SessionMessageType::ModificationCommand,
            0b11001100 => SessionMessageType::ModificationComplete,
            0b11001101 => SessionMessageType::ModificationCommandReject,

            0b11010001 => SessionMessageType::ReleaseRequest,
            0b11010010 => SessionMessageType::ReleaseReject,
            0b11010011 => SessionMessageType::ReleaseCommand,
            0b11010100 => SessionMessageType::ReleaseComplete,

            _ => SessionMessageType::Unknown,
        }
    }
    pub fn default() -> SessionMessageType {
        SessionMessageType::EstablishmentAccept
    }
}
#[repr(C)]
#[derive(Debug)]
pub struct PduSessionEstablishmentAcceptMsg {
    pub extendedprotocoldiscriminator: ExtendedProtocolDiscriminator,
    pub pdusessionidentity: PDUSessionIdentity,
    pub proceduretransactionidentity: ProcedureTransactionIdentity,
    pub messagetype: SessionMessageType,
    pub pdusessiontype: PDUSessionType,
    pub sscmode: SSCMode,
    pub qosrules: QOSRules,
    // sessionambr: SessionAMBR,
    // presence: u16,
    // _5gsmcause: _5GSMCause,
    pub pduaddress: PDUAddress,
    // gprstimer: GPRSTimer,
    // snssai: SNSSAI,
    // alwaysonpdusessionindication: AlwaysonPDUSessionIndication,
    // mappedepsbearercontexts: MappedEPSBearerContexts,
    // eapmessage: EAPMessage,
    pub qosflowdescriptions: QOSFlowDescriptions,
    pub extendedprotocolconfigurationoptions: ExtProtoCfgOpts,
    pub dnn: DNN,
}

pub type ExtendedProtocolDiscriminator = u8;

pub type PDUSessionIdentity = u8;

pub type ProcedureTransactionIdentity = u8;

// pub type MessageType = u8;

#[repr(C)]
#[derive(Debug, PartialEq)]

pub struct PDUSessionType {
    pub pdu_session_type_value: PduAddressType,
    pub spare: u8,
}

impl PDUSessionType {
    fn default() -> Self {
        PDUSessionType {
            pdu_session_type_value: PduAddressType::IPV4,
            spare: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug)]

pub struct SSCMode {
    pub sscModeValue: u8,
    pub spare: u8,
}

#[repr(C)]
// pub struct PacketFilterContents {
//     pub component_type: u8,
//     pub component_value: OctetString,
// }

// // impl PacketFilterContents {
// //     fn default() -> Self {
// //         PacketFilterContents {
// //             component_type: 0,
// //             component_value: 0,
// //         }
// //     }
// // }

// #[repr(C)]
// pub struct Create_ModifyAndAdd_ModifyAndReplace {
//     pub packetfilteridentifier: u8,
//     pub packetfilterdirection: u8,
//     pub spare: u8,
//     pub lenghtofpacketfiltercontents: u8,
//     pub packetfiltercontents: PacketFilterContents,
// }

// impl Create_ModifyAndAdd_ModifyAndReplace {
//     fn default() -> Self {
//         Create_ModifyAndAdd_ModifyAndReplace {
//             packetfilteridentifier: 0,
//             packetfilterdirection: 0,
//             spare: 0,
//             lenghtofpacketfiltercontents: 0,
//             packetfiltercontents: 0,
//         }
//     }
// }
#[repr(C)]
#[derive(Debug)]

pub struct QOSRulesIE {
    pub qosruleidentifer: u8,
    pub lengthof_qo_srule: u16,
    pub numberofpacketfilters: u8,
    pub dqrbit: u8,
    /**
    * Rule operation code (bits 8 to 6 of octet 7)
           Bits
           8 7 6
           0 0 0	Reserved
           0 0 1	Create new QoS rule
           0 1 0	Delete existing QoS rule
           0 1 1	Modify existing QoS rule and add packet filters
           1 0 0	Modify existing QoS rule and replace all packet filters
           1 0 1	Modify existing QoS rule and delete packet filters
           1 1 0	Modify existing QoS rule without modifying packet filters
           1 1 1	Reserved
    */
    pub ruleoperationcode: RuleOperationCode,
    pub packetfilterlist: PacketFilterListEnum,
    pub qosruleprecedence: u8,
    pub qosflowidentifer: u8,
    pub segregation: u8,
    pub spare: u8,
}
#[derive(Debug)]
pub enum RuleOperationCode {
    Reserved,
    CreateNewQosRule = 0b00000001,
    DeleteExistingQosRule = 0b00000010,
    ModifyExistingQosRuleAndAddPackerFilters = 0b00000011,
    ModifyExistingQosRuleAndReplacePackerFilters = 0b00000100,
    ModifyExistingQosRuleAndDeletePackerFilters = 0b00000101,
    ModifyExistingQosRuleWithoutModifyPackerFilters = 0b00000110,
    
}
impl RuleOperationCode {
    pub fn from_u8(data: u8) -> RuleOperationCode {
        match data {
            0b00000001 =>{
                RuleOperationCode::CreateNewQosRule
            },
            0b00000010 =>{
                RuleOperationCode::DeleteExistingQosRule
            },
            0b00000011 =>{
                RuleOperationCode::ModifyExistingQosRuleAndAddPackerFilters
            },
            0b00000100 =>{
                RuleOperationCode::ModifyExistingQosRuleAndReplacePackerFilters
            },
            0b00000101 =>{
                RuleOperationCode::ModifyExistingQosRuleAndDeletePackerFilters
            },
            0b00000110 =>{
                RuleOperationCode::ModifyExistingQosRuleWithoutModifyPackerFilters
            },
            _ => {
                RuleOperationCode::Reserved
            }
        }
    }
}
// impl QOSRulesIE {
//     fn default() -> Self {
//         QOSRulesIE {
//             qosruleidentifer: 0,
//             LengthofQoSrule: 0,
//             numberofpacketfilters: 0,
//             dqrbit: 0,
//             ruleoperationcode: 0,
//             packetfilterlist: 0,
//             qosruleprecedence: 0,
//             qosflowidentifer: 0,
//             segregation: 0,
//             spare: 0,
//         }
//     }
// }

#[derive(Debug)]
pub enum PacketFilterListEnum {
    PacketFilterListDeletePFList(PacketFilterListDeletePFList),
    PacketFilterListUpdatePFList(PacketFilterListUpdatePFList),
    PacketFilterListOpOnePF(PacketFilterSingle),
    PacketFilterNone,
}

#[derive(Debug)]

pub struct PacketFilterSingle {
    pub packet_fliter_id: u8,
}

#[repr(C)]
#[derive(Debug)]

pub struct PacketFilterListDeletePFList {
    pub packet_fliter_id: Vec<u8>,
}
#[repr(C)]
#[derive(Debug)]

pub struct PacketFilterListUpdatePFList {
    pub packet_filter_direction: u8,
    pub packet_filter_id: u8,
    pub length_packet_filter_contents: u8,
    pub packet_filter_content_list: Vec<PacketFilterContent>,
}

#[derive(Debug)]
pub struct PacketFilterContent {
    pub packet_filter_content_type: PacketFilterComponentType,
    pub packet_filter_content_value: PacketFilterComponentValue,
}
#[derive(Debug)]
pub enum PacketFilterComponentType {
    MatchAll = 0b00000001,
    IPv4RemoteAddress = 0b00001001,
    IPv4LocalAddress = 0b00001010,
    IPv6RemoteAddressPrefixLength = 0b00001100,
    IPv6LocalAddressPrefixLength = 0b00001111,

    ProtocolIdentifierNextHeader = 0b00010000,
    SingleLocalPort = 0b00010001,
    LocalPortRange = 0b00010010,
    SingleRemotePort = 0b00010011,
    RemotePortRange = 0b00010100,

    SecurityParameterIndex = 0b00011000,
    TypeOfServiceTrafficClass = 0b00011001,
    FlowLabel = 0b00100000,

    DestinationMACAddress = 0b00100001,
    SourceMACAddress = 0b00100010,
    VlanCtagVid = 0b00100011,
    VlanStagVid = 0b00100100,
    VlanCtagPcpdei = 0b00100101,
    VlanStagPcpdei = 0b00100110,
    Ethertype = 0b00100111,

    DestinationMACAddressRange = 0b00101000,
    SourceMACAddressRange = 0b00101001,
}
impl PacketFilterComponentType {
    pub fn from_u8(data: u8) -> PacketFilterComponentType {
        match data {
            // MatchAll = 0b00000001,
            0b00000001 => PacketFilterComponentType::MatchAll,
            // IPv4RemoteAddress = 0b00001001,
            0b00001001 => PacketFilterComponentType::IPv4RemoteAddress,

            // IPv4LocalAddress = 0b00001010,
            0b00001010 => PacketFilterComponentType::IPv4LocalAddress,
            // IPv6RemoteAddressPrefixLength = 0b00001100,
            0b00001100 => PacketFilterComponentType::IPv6RemoteAddressPrefixLength,
            // IPv6LocalAddressPrefixLength = 0b00001111,
            0b00001111 => PacketFilterComponentType::IPv6LocalAddressPrefixLength,

            // ProtocolIdentifierNextHeader = 0b00010000,
            0b00010000 => PacketFilterComponentType::ProtocolIdentifierNextHeader,
            // SingleLocalPort = 0b00010001,
            0b00010001 => PacketFilterComponentType::SingleLocalPort,
            // LocalPortRange = 0b00010010,
            0b00010010 => PacketFilterComponentType::LocalPortRange,
            // SingleRemotePort = 0b00010011,
            0b00010011 => PacketFilterComponentType::SingleRemotePort,
            // RemotePortRange = 0b00010100,
            0b00010100 => PacketFilterComponentType::RemotePortRange,

            // SecurityParameterIndex = 0b00011000,
            0b00011000 => PacketFilterComponentType::SecurityParameterIndex,
            // TypeOfServiceTrafficClass = 0b00011001,
            0b00011001 => PacketFilterComponentType::TypeOfServiceTrafficClass,
            // FlowLabel = 0b00100000,
            0b00100000 => PacketFilterComponentType::FlowLabel,

            // DestinationMACAddress = 0b00100001,
            0b00100001 => PacketFilterComponentType::DestinationMACAddress,
            // SourceMACAddress = 0b00100010,
            0b00100010 => PacketFilterComponentType::SourceMACAddress,
            // VlanCtagVid = 0b00100011,
            0b00100011 => PacketFilterComponentType::VlanCtagVid,
            // VlanStagVid = 0b00100100,
            0b00100100 => PacketFilterComponentType::VlanStagVid,
            // VlanCtagPcpdei = 0b00100101,
            0b00100101 => PacketFilterComponentType::VlanCtagPcpdei,
            // VlanStagPcpdei = 0b00100110,
            0b00100110 => PacketFilterComponentType::VlanStagPcpdei,
            // Ethertype = 0b00100111,
            0b00100111 => PacketFilterComponentType::Ethertype,
            _ => PacketFilterComponentType::Ethertype,
        }
    }
}
#[derive(Debug)]
pub enum PacketFilterComponentValue {
    /*For "match-all type", the packet filter component shall not include the packet filter component value field. */
    MatchAll,
    IPv4RemoteAddress(IPv4FilterAddress),
    IPv4LocalAddress(IPv4FilterAddress),
    IPv6RemoteAddressPrefixLength(IPv6FilterAddress),
    IPv6LocalAddressPrefixLength(IPv6FilterAddress),

    ProtocolIdentifierNextHeader(ProtocolIdentifierNextHeader),
    SingleLocalPort(Port),
    LocalPortRange(PortRange),
    SingleRemotePort(Port),
    RemotePortRange(PortRange),

    SecurityParameterIndex(SecurityParameterIndex),
    TypeOfServiceTrafficClass(TypeOfServiceTrafficClass),
    FlowLabel(FlowLabel),

    DestinationMACAddress(MACAddress),
    SourceMACAddress(MACAddress),
    VlanCtagVid(VlanCtagVid),
    VlanStagVid(VlanStagVid),
    VlanCtagPcpdei(VlanCtagPcpdei),
    VlanStagPcpdei(VlanStagPcpdei),
    Ethertype(Ethertype),
    DestinationMACAddressRange(DestinationMACAddressRange),
    SourceMACAddressRange(SourceMACAddressRange),
}

#[derive(Debug)]

pub struct IPv4FilterAddress {
    /*
     * 对于"IPv4远程/本地地址类型",数据包过滤器组件值字段应编码为
     * 一个四个八位字节的IPv4地址字段和一个四个八位字节的IPv4地址掩码字段序列。
     * IPv4地址字段应首先传输。
     * For "IPv4 remote/local address type", the packet filter component value field shall be encoded as a sequence of a four octet IPv4 address field and a four octet IPv4 address mask field. The IPv4 address field shall be transmitted first.
     */
    ipv4_address: Vec<u8>,
    ipv4_address_mask: Vec<u8>,
}

#[derive(Debug)]
/*
 * 对于"IPv6远程地址/前缀长度类型",数据包过滤器组件值字段应编码为
 * 一个十六个八位字节的IPv6地址字段和一个八位字节的前缀长度字段序列。
 * IPv6地址字段应首先传输。
 */
pub struct IPv6FilterAddress {
    /* For "IPv6 remote address/prefix length type", the packet filter component value field shall be encoded as a sequence of a sixteen octet IPv6 address field and one octet prefix length field. The IPv6 address field shall be transmitted first.
     */
    ipv6_address: Vec<u8>,
    prefix_length: u8,
}

#[derive(Debug)]
/*
 * 对于“协议标识符/下一头类型”,数据包过滤器组件值字段应编码为一个八位字节,
 * 该字节指定IPv4协议标识符或IPv6下一头。
 */
pub struct ProtocolIdentifierNextHeader {
    /*For "protocol identifier/Next header type", the packet filter component value field shall be encoded as one octet which specifies the IPv4 protocol identifier or Ipv6 next header. */
    value: u8,
}

#[derive(Debug)]
pub struct Port {
    /*For "single local port type" and "single remote port type", the packet filter component value field shall be encoded as two octets which specify a port number. */
    value: u16,
}

#[derive(Debug)]
pub struct PortRange {
    /*For "local port range type" and "remote port range type", the packet filter component value field shall be encoded as a sequence of a two octet port range low limit field and a two octet port range high limit field. The port range low limit field shall be transmitted first. */
    low: u16,
    high: u16,
}

#[derive(Debug)]
pub struct SecurityParameterIndex {
    /*
     * 对于“安全参数索引”,数据包过滤器组件值字段应编码为四个八位字节,
     * 用于指定IPSec安全参数索引。
     */
    value: u32,
}

#[derive(Debug)]
pub struct TypeOfServiceTrafficClass {
    /*For "type of service/traffic class type", the packet filter component value field shall be encoded as a sequence of a one octet type-of-service/traffic class field and a one octet type-of-service/traffic class mask field. The type-of-service/traffic class field shall be transmitted first. */
    /*
     * 对于“服务类型/通信类别类型”,数据包过滤器组件值字段应编码为
     * 一个八位字节的服务类型/通信类别字段和一个八位字节的服务类型/通信类别掩码字段序列。
     * 服务类型/通信类别字段应首先传输。
     */
    value: u8,
    mask: u8,
}
#[derive(Debug)]
pub struct FlowLabel {
    /*For "flow label type", the packet filter component value field shall be encoded as three octets which specify the IPv6 flow label. The bits 8 through 5 of the first octet shall be spare whereas the remaining 20 bits shall contain the IPv6 flow label. */
    /*
     * 对于“流标签类型”,数据包过滤器组件值字段应编码为三个八位字节,
     * 用于指定IPv6流标签。第一个八位字节的第8至5位应为零,其余20位应包含IPv6流标签。
     */
    value: u32,
}
#[derive(Debug)]
pub struct MACAddress {
    /*For "destination MAC address type" and "source MAC address type", the packet filter component value field shall be encoded as 6 octets which specify a MAC address. When the packet filter direction field indicates "bidirectional", the destination MAC address is the remote MAC address and the source MAC address is the local MAC address. */
    /*
     * 对于“目的MAC地址类型”和“源MAC地址类型”,数据包过滤器组件值字段应编码为6个八位字节,
     * 用于指定一个MAC地址。当数据包过滤器方向字段表示“双向”时,目的MAC地址是远程MAC地址,
     * 源MAC地址是本地MAC地址。
     */
    value: Vec<u8>,
}
#[derive(Debug)]
pub struct VlanCtagVid {
    /*For "802.1Q C-TAG VID type", the packet filter component value field shall be encoded as two octets which specify the VID of the customer-VLAN tag (C-TAG). The bits 8 through 5 of the first octet shall be spare whereas the remaining 12 bits shall contain the VID. If there are more than one C-TAG in the Ethernet frame header, the outermost C-TAG is evaluated.
     */
    // ...
}
#[derive(Debug)]
pub struct VlanStagVid {
    /*For "802.1Q S-TAG VID type", the packet filter component value field shall be encoded as two octets which specify the VID of the service-VLAN tag (S-TAG). The bits 8 through 5 of the first octet shall be spare whereas the remaining 12 bits shall contain the VID. If there are more than one S-TAG in the Ethernet frame header, the outermost S-TAG is evaluated. */
    // ...
}
#[derive(Debug)]
pub struct VlanCtagPcpdei {
    /*For "802.1Q C-TAG PCP/DEI type", the packet filter component value field shall be encoded as one octet which specifies the 802.1Q C-TAG PCP and DEI. The bits 8 through 5 of the octet shall be spare, the bits 4 through 2 contain the PCP and bit 1 contains the DEI. If there are more than one C-TAG in the Ethernet frame header, the outermost C-TAG is evaluated */
    // ...
}
#[derive(Debug)]
pub struct VlanStagPcpdei {
    /*For "802.1Q S-TAG PCP/DEI type", the packet filter component value field shall be encoded as one octet which specifies the 802.1Q S-TAG PCP. The bits 8 through 5 of the octet shall be spare, the bits 4 through 2 contain the PCP and bit 1 contains the DEI. If there are more than one S-TAG in the Ethernet frame header, the outermost S-TAG is evaluated */
    // ...
}
#[derive(Debug)]
pub struct Ethertype {
    /*For "ethertype type", the packet filter component value field shall be encoded as two octets which specify an ethertype */
    // ...
}
#[derive(Debug)]
pub struct DestinationMACAddressRange {
    /*For "destination MAC address range type", the packet filter component value field shall be encoded as a sequence of a 6 octet destination MAC address range low limit field and a 6 octet destination MAC address range high limit field. The destination MAC address range low limit field shall be transmitted first. When the packet filter direction field indicates "bidirectional", the destination MAC address range is the remote MAC address range. */
    // ...
}
#[derive(Debug)]
pub struct SourceMACAddressRange {
    /*For "source MAC address range type", the packet filter component value field shall be encoded as a sequence of a 6 octet source MAC address range low limit field and a 6 octet source MAC address range high limit field. The source MAC address range low limit field shall be transmitted first. When the packet filter direction field indicates "bidirectional", the source MAC address is the local MAC address range. */
    // ...
}

#[repr(C)]
#[derive(Debug)]

pub struct QOSRules {
    pub lengthofqosrulesie: u16,
    pub qosrulesie: Vec<QOSRulesIE>,
}

// #[repr(C)]
// #[derive(Debug)]

// pub struct SessionAMBR {
//     pub uint_for_session_ambr_for_downlink: u8,
//     pub session_ambr_for_downlink: u16,
//     pub uint_for_session_ambr_for_uplink: u8,
//     pub session_ambr_for_uplink: u16,
// }

// pub type _5GSMCause = u8;
#[repr(C)]
#[derive(Debug)]

pub struct PDUAddress {
    pub pdu_session_type_value: PduAddressType,
    // pub spare: u8,
    pub pdu_address_information: OctetString,
}
impl PDUAddress {
    pub fn default() -> Self {
        PDUAddress {
            pdu_session_type_value: PduAddressType::IPV4,
            // spare: 0,
            pdu_address_information: OctetString::default(),
        }
    }
}

fn decode_dnn(input: *mut u8) -> String {
    let len = unsafe { std::ptr::read(input.offset(0)) } as usize;

    let dnn_bytes = unsafe {
        let ptr = input.offset(1) as *const u8;
        std::slice::from_raw_parts(ptr, len)
    };

    let dnn = std::str::from_utf8(dnn_bytes).unwrap();

    let dnn_components: Vec<&str> = dnn.split('.').collect();
    let dnn = dnn_components.join(".");

    // input = &mut input[len+1..];

    dnn
}

#[repr(C)]
#[derive(Debug)]

pub struct OctetString {
    pub length: u32,
    pub value: *mut u8,
}
impl OctetString {
    fn default() -> Self {
        OctetString {
            length: 0,
            value: std::ptr::null_mut(),
        }
    }
    pub fn set_value(&mut self, data: &[u8], start_index: usize, length: usize) {
        self.length = length as u32;
        self.value = std::ptr::null_mut(); // 重置value指针

        if length > 0 {
            let layout = Layout::array::<u8>(length).unwrap();
            self.value = unsafe { alloc(layout) as *mut u8 };
            unsafe {
                std::ptr::copy_nonoverlapping(data.as_ptr().add(start_index), self.value, length);
            }
        }
    }

    pub fn to_string(&mut self) -> &str {
        let string: &str;
        unsafe {
            let slice = slice::from_raw_parts(self.value, self.length.try_into().unwrap());
            string = std::str::from_utf8(slice).unwrap();
        };
        return string;
    }

    pub fn dnn_to_string(&mut self) -> String {
        let string = decode_dnn(self.value);
        return string;
    }

    pub fn to_bytes_u8(&mut self) -> &[u8] {
        let mut _string: &str;
        let slice: &[u8];
        unsafe {
            slice = slice::from_raw_parts(self.value, self.length.try_into().unwrap());
        };
        return slice;
    }
}

// #[repr(C)]
// #[derive(Debug)]

// pub struct GPRSTimer {
//     pub timeValue: u8,
//     pub unit: u8,
// }

// #[repr(u8)]
// #[derive(Debug)]
// pub enum length_of_snssai_contents {
//     SST_LENGTH = 0b00000001,
//     SST_AND_MAPPEDHPLMNSST_LENGTH = 0b00000010,
//     SST_AND_SD_LENGTH = 0b00000100,
//     SST_AND_SD_AND_MAPPEDHPLMNSST_LENGTH = 0b00000101,
//     SST_AND_SD_AND_MAPPEDHPLMNSST_AND_MAPPEDHPLMNSD_LENGTH = 0b00001000,
// }

// #[repr(C)]
// #[derive(Debug)]

// pub struct SNSSAI {
//     pub len: length_of_snssai_contents,
//     pub sst: u8,
//     pub sd: [u8; 3],
//     pub mappedhplmnsst: u8,
//     pub mappedhplmnsd: [u8; 3],
// }

// #[repr(C)]
// #[derive(Debug)]

// pub struct AlwaysonPDUSessionIndication {
//     pub apsi_indication: u8,
//     pub spare: u8,
// }

// pub type MappedEPSBearerContexts = OctetString;
// pub type EAPMessage = OctetString;

// #[repr(C)]
// #[derive(Debug)]
// pub struct ParametersList {
//     pub parameteridentifier: u8,
//     pub lengthofparametercontents: u8,
//     pub parametercontents: ParametersListContents,
// }

// #[repr(C)]
// #[derive(Debug)]
// pub struct ParametersListContents {
//     pub _5qi: u8,
//     pub gfbrormfbr_uplinkordownlink: GFBROrMFBR_UpLinkOrDownLink,
//     pub averagingwindow: AveragingWindow,
//     pub epsbeareridentity: EpsBearerIdentity,
// }
// #[repr(C)]
// #[derive(Debug)]
// pub struct EpsBearerIdentity {
//     pub spare: u8,
//     pub identity: u8,
// }

// #[repr(C)]
#[derive(Debug)]
pub struct QOSFlowDescriptionsContents {
    pub qfi: u8,
    pub operationcode: u8,
    pub numberofparameters: u8,
    pub e: u8,
    pub parameterslist: Vec<Parameter>,
}
#[derive(Debug)]
pub struct Parameter {
    pub parameter_id: u8,
    pub length_param_content: u8,
    // pub contents: Vec<ParametersList>,
}

// #[repr(C)]
#[derive(Debug)]
pub struct QOSFlowDescriptions {
    pub qosflowdescriptionsnumber: u16,
    pub qosflowdescriptionscontents: Vec<QOSFlowDescriptionsContents>,
}
impl QOSFlowDescriptions {
    pub fn default() -> QOSFlowDescriptions {
        QOSFlowDescriptions {
            qosflowdescriptionsnumber: 0,
            qosflowdescriptionscontents: vec![],
        }
    }
}

// #[repr(C)]
// #[derive(Debug)]

// pub struct GFBROrMFBR_UpLinkOrDownLink {
//     pub uint: u8,
//     pub value: u16,
// }

// #[repr(C)]
// #[derive(Debug)]

// pub struct AveragingWindow {
//     pub uplinkinmilliseconds: u8,
//     pub downlinkinmilliseconds: u8,
// }

// #[repr(C)]
// #[derive(Debug)]

// pub struct ExtendedProtocolConfigurationOptions {
//     pub configurationProtocol: u8,
//     pub spare: u8,
//     pub ext: u8,
//     pub numerofProtocolId: u8,
//     pub protocolId: *mut ProtocolIdContents,
// }

// #[repr(C)]
// #[derive(Debug)]

// pub struct ProtocolIdContents {
//     pub id: u16,
//     pub lengthofContents: u8,
//     pub contents: OctetString,
// }

pub type DNN = OctetString;

impl PduSessionEstablishmentAcceptMsg {
    pub fn new() -> Self {
        PduSessionEstablishmentAcceptMsg {
            extendedprotocoldiscriminator: ExtendedProtocolDiscriminator::default(),
            pdusessionidentity: PDUSessionIdentity::default(),
            proceduretransactionidentity: ProcedureTransactionIdentity::default(),
            messagetype: SessionMessageType::default(),
            pdusessiontype: PDUSessionType::default(),
            // sscmode: SSCMode::default(),
            // qosrules: QOSRules::default(),
            // sessionambr: SessionAMBR::default(),
            // presence: 0,
            // _5gsmcause: _5GSMCause::default(),
            pduaddress: PDUAddress::default(),
            // gprstimer: GPRSTimer::default(),
            // snssai: SNSSAI::default(),
            // alwaysonpdusessionindication: AlwaysonPDUSessionIndication::default(),
            // mappedepsbearercontexts: MappedEPSBearerContexts::default(),
            // eapmessage: EAPMessage::default(),
            qosflowdescriptions: QOSFlowDescriptions {
                qosflowdescriptionsnumber: 0,
                qosflowdescriptionscontents: vec![],
            },
            extendedprotocolconfigurationoptions: ExtProtoCfgOpts::default(),
            dnn: DNN::default(),
            sscmode: SSCMode {
                sscModeValue: 0u8,
                spare: 0u8,
            },
            qosrules: QOSRules {
                lengthofqosrulesie: 0,
                qosrulesie: vec![],
            },
        }
    }

    pub fn get_dnn_name(&mut self) -> String {
        if self.dnn.length > 0 {
            return self.dnn.dnn_to_string();
        } else {
            return "".to_string();
        }
    }

    pub fn get_ipv4(&mut self) -> Result<IpAddr, &str> {
        let arr = self.pduaddress.pdu_address_information.to_bytes_u8();
        let mut _ipv6_str: String;
        let mut _ipv4_str: String;
        if arr.len() == 4 {
            let ipv4_bytes: [u8; 4] = [arr[0], arr[1], arr[2], arr[3]];
            let ipv4_addr = Ipv4Addr::from(ipv4_bytes);

            Ok(IpAddr::V4(ipv4_addr))
        } else if arr.len() == 8 {
            Err("")
        } else if arr.len() == 12 {
            let ipv6_bytes: [u8; 16] = [
                0, 0, 0, 0, 0, 0, 0, 0, arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6],
                arr[7],
            ];
            let ipv4_bytes: [u8; 4] = [arr[8], arr[9], arr[10], arr[11]];
            let _ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            let ipv4_addr = Ipv4Addr::from(ipv4_bytes);
            Ok(IpAddr::V4(ipv4_addr))
        } else {
            Err("")
        }
    }

    pub fn _get_ipv6(&mut self) -> Result<IpAddr, &str> {
        let arr = self.pduaddress.pdu_address_information.to_bytes_u8();
        let mut _ipv6_str: String;
        let mut _ipv4_str: String;
        if arr.len() == 4 {
            Err("")
        } else if arr.len() == 8 {
            let ipv6_bytes: [u8; 16] = [
                0, 0, 0, 0, 0, 0, 0, 0, arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6],
                arr[7],
            ];
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            Ok(IpAddr::V6(ipv6_addr))
        } else if arr.len() == 12 {
            let ipv6_bytes: [u8; 16] = [
                0, 0, 0, 0, 0, 0, 0, 0, arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6],
                arr[7],
            ];
            let ipv4_bytes: [u8; 4] = [arr[8], arr[9], arr[10], arr[11]];
            let ipv6_addr = Ipv6Addr::from(ipv6_bytes);
            let _ipv4_addr = Ipv4Addr::from(ipv4_bytes);
            Ok(IpAddr::V6(ipv6_addr))
        } else {
            Err("")
        }
    }

    pub fn get_pcscf_v6_address(&mut self) -> Ipv6Addr {
        let v6_addr = self
            .extendedprotocolconfigurationoptions
            .get_pcscf_v6_addr()
            .unwrap_or(Ipv6Addr::LOCALHOST);
        v6_addr
    }
    pub fn get_dns_v6_address(&mut self) -> Option<Ipv6Addr> {
        return self
            .extendedprotocolconfigurationoptions
            .get_pcscf_v6_addr();
    }
}

const PDU_SESSION_ESTABLISHMENT_ACCEPT_5_GSM_CAUSE_IEI: u8 = 0x59;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_RQ_TIMER_IEI: u8 = 0x56;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYS_ON_IEI: u8 = 0x08;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_CP_ONLY_IEI: u8 = 0xc0;

const PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_IEI: u8 = 0x56;

const PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_IEI: u8 = 0x29;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_IEI: u8 = 0x22;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_IEI: u8 = 0x80;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_IEI: u8 = 0x75;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_IEI: u8 = 0x78;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_IEI: u8 = 0x79;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_IEI: u8 = 0x7B;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_ATSSS_IEI: u8 = 0x77;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_IEI: u8 = 0x25;

const PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_PRESENCE: u16 = 1 << 0;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_PRESENCE: u16 = 1 << 1;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_PRESENCE: u16 = 1 << 2;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_PRESENCE: u16 = 1 << 3;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE: u16 = 1 << 4;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_PRESENCE: u16 = 1 << 5;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_PRESENCE: u16 = 1 << 6;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_PRESENCE: u16 = 1 << 7;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_PRESENCE: u16 = 1 << 8;
const PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_PRESENCE: u16 = 1 << 9;

pub const _NR_NETWORK_IF_MGMT_CREATE: u8 = 0x00;
pub const _NR_NETWORK_IF_MGMT_UPDATE: u8 = 0x01;
pub const _NR_NETWORK_IF_MGMT_DELETE: u8 = 0x11;
pub const _NR_NETWORK_IF_MGMT_DESTORY: u8 = 0xff;

pub fn tlv_decode_nr_network_if_mgm(data: &[u8]) -> Option<(u8, Vec<u8>)> {
    let mut index = 0;
    while index < data.len() {
        let current_tag = data[index];
        let length = data[index + 1] as usize;

        if current_tag == _NR_NETWORK_IF_MGMT_CREATE {
            let value = data[index + 2..index + 2 + length].to_vec();
            return Some((current_tag, value));
        }

        if current_tag == _NR_NETWORK_IF_MGMT_UPDATE {
            let value = data[index + 2..index + 2 + length].to_vec();
            return Some((current_tag, value));
        }

        if current_tag == _NR_NETWORK_IF_MGMT_DESTORY {
            let value = Vec::new();
            return Some((current_tag, value));
        }

        index += 2 + length;
    }

    None
}

/**
 * 3GPP TS 24501 8.3.2.1
 */
pub fn tlv_decode_pdu_session_establishment_accept(
    data: Vec<u8>,
) -> Option<PduSessionEstablishmentAcceptMsg> {
    let mut index: usize = 0;
    let mut res: PduSessionEstablishmentAcceptMsg = PduSessionEstablishmentAcceptMsg::new();
    println!("{:?}", data);
    //decode extended_protocol_discriminator
    res.extendedprotocoldiscriminator = data[index];
    index += 1;
    //decode_pdu_session_identity/scc
    res.pdusessionidentity = data[index];
    index += 1;
    //decode_procedure_transaction_identity
    res.proceduretransactionidentity = data[index];
    index += 1;
    //decode_message_type
    index += 1;
    //seleted pdu session type and seleted ssc mode are in one octet!
    res.pdusessiontype.pdu_session_type_value = PduAddressType::from_u8(data[index] & 0b00000111);
    index += 1;
    //decode_qos_rules
    let value: u16 = (data[index] as u16) << 8 | data[index + 1] as u16;
    res.qosrules = QOSRules::decode(data[index..].to_vec());
    let length = value as usize;
    index += 2;
    index += length;
    //decode_session_ambr
    let length1 = data[index] as usize;
    index += 1;
    index += length1;

    //begin TLV

    while index < data.len() {
        let current_tag = data[index];
        let length: usize;
        let is_match = match current_tag {
            PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_IEI
            | PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_IEI
            | PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_IEI
            | PDU_SESSION_ESTABLISHMENT_ACCEPT_ATSSS_IEI
            | PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_IEI => 1,
            PDU_SESSION_ESTABLISHMENT_ACCEPT_5_GSM_CAUSE_IEI
            | PDU_SESSION_ESTABLISHMENT_ACCEPT_RQ_TIMER_IEI => 2,
            PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_IEI
            | PDU_SESSION_ESTABLISHMENT_ACCEPT_CP_ONLY_IEI => 3,
            _ => 0,
        };

        if is_match == 1 {
            let value: u16 = (data[index + 1] as u16) << 8 | data[index + 2] as u16;
            length = value as usize;
            println!("TLV-E {} index {} len {}", current_tag, index, length);
        } else if is_match == 0 {
            length = data[index + 1] as usize;
            println!("TLV {} index {}", current_tag, index);
        } else if is_match == 2 {
            length = 2;
            println!("TV 2 {} index {}", current_tag, index);
        } else {
            length = 1;
            println!("TV 1 {} index {}", current_tag, index);
        }

        if current_tag == PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_IEI {
            let value = data[index + 2..index + 2 + length].to_vec();
            let _dnn_index = res.dnn.set_value(&value, 0, length);
            // let string = std::str::from_utf8(&value).unwrap(); // 解析切片为字符串
            res.dnn.to_string();
        }

        if current_tag == PDU_SESSION_ESTABLISHMENT_ACCEPT_EPCO_IEI {
            let value = data[index..index + 3 + length].to_vec();
            // let string = std::str::from_utf8(&value).unwrap(); // 解析切片为字符串
            // print!("{:#?}\n",value);
            res.extendedprotocolconfigurationoptions = parse_extended_pco(&value).unwrap();
        }

        if current_tag == PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_IEI {
            let ip_len;

            let value = data[index + 2..index + 2 + length].to_vec();
            res.pduaddress.pdu_session_type_value = PduAddressType::from_u8(value[0]);
            if res.pduaddress.pdu_session_type_value == PduAddressType::IPV4 {
                ip_len = 4;
            } else if res.pduaddress.pdu_session_type_value == PduAddressType::IPV6 {
                ip_len = 8;
            } else if res.pduaddress.pdu_session_type_value == PduAddressType::IPV4V6 {
                ip_len = 12;
            } else {
                ip_len = 4;
            }
            res.pduaddress
                .pdu_address_information
                .set_value(&value, 1, ip_len);
        }

        if is_match == 1 {
            index += 3 + length;
        } else if is_match == 0 {
            index += 2 + length;
        } else if is_match == 2 {
            index += length;
        } else {
            index += length;
        }
    }
    return Some(res);
}
impl QOSRules {
    fn decode(data: Vec<u8>) -> QOSRules {
        let mut index = 0;
        let length: u16 = (data[index] as u16) << 8 | data[index + 1] as u16;
        let mut qosRulesIEList: Vec<QOSRulesIE> = vec![];
        index += 2; //decoder header
        while index < length.into() {
            // { qosruleidentifer: val, LengthofQoSrule: val, numberofpacketfilters: val, dqrbit: val, ruleoperationcode: val,
            // packetfilterlist: val, qosruleprecedence: val, qosflowidentifer: val, segregation: val, spare: val }
            let qosruleidentifer: u8 = data[index];
            index += 1;
            let LengthofQoSrule: u16 = (data[index] as u16) << 8 | data[index + 1] as u16;
            index += 2;
            // octet 7
            let numberofpacketfilters = data[index] & 0b00001111;
            let dqrbit = (data[index] & 0b00010000) >> 4;
            let ruleoperationcode = RuleOperationCode::from_u8((data[index] & 0b11100000) >> 5);
            index += 1;
            // let mut PacketFilterListEnum { packet_filter_direction, packet_filter_id, length_packet_filter_contents, packet_filter_content_list }
            // let packetFilterListEnum:PacketFilterListEnum =
            let packetfilterlist = match ruleoperationcode {
                RuleOperationCode::ModifyExistingQosRuleAndDeletePackerFilters => {
                    //Modify existing QoS rule and delete packet filters
                    //For the "modify existing QoS rule and delete packet filters" operation,
                    //the packet filter list shall contain a variable number of packet filter
                    //identifiers. This number shall be derived from the coding of the number of packet filters field in octet 7
                    let mut packetFilterListDeletePF = PacketFilterListDeletePFList {
                        packet_fliter_id: vec![],
                    };
                    for i in index..(index + numberofpacketfilters as usize) - 1 {
                        packetFilterListDeletePF
                            .packet_fliter_id
                            .push(data[index] & 0b00001111);
                        index += 1;
                    }
                    PacketFilterListEnum::PacketFilterListDeletePFList(packetFilterListDeletePF)
                }
                RuleOperationCode::DeleteExistingQosRule | RuleOperationCode::ModifyExistingQosRuleWithoutModifyPackerFilters => {
                    //Delete existing QoS rule | modify existing QoS rule without modifying packet filters
                    //For the "delete existing QoS rule" operation, the length of QoS rule field is set to one.
                    //For the "delete existing QoS rule" operation and the "modify existing QoS rule without modifying packet filters" operation, the packet filter list shall be empty.
                    PacketFilterListEnum::PacketFilterNone
                }
                RuleOperationCode::CreateNewQosRule | 
                RuleOperationCode::ModifyExistingQosRuleAndAddPackerFilters | 
                RuleOperationCode::ModifyExistingQosRuleAndReplacePackerFilters => {
                    // Create new QoS rule | Modify existing QoS rule and add packet filters | Modify existing QoS rule and replace all packet filters
                    //For the "create new QoS rule" operation and for the "modify existing
                    //QoS rule and replace all packet filters" operation, the packet filter
                    //list shall contain 0 or a variable number of packet filters. This number
                    //shall be derived from the coding of the number of packet filters field in octet 7
                    // let mut packetFilterListUpdatePFList = PacketFilterListUpdatePFList { packet_filter_direction: todo!(), packet_filter_id: todo!(), length_packet_filter_contents: todo!(), packet_filter_content_list: todo!() }
                    let packet_filter_direction = (data[index] & 0b00110000) >> 4;
                    let packet_filter_id = data[index] & 0b00001111;
                    index += 1;
                    let length_packet_filter_contents = data[index];
                    //let mut packetFilterUpdatePF =
                    //PacketFilterListUpdatePFList { packet_filter_direction, packet_filter_id, length_packet_filter_contents, packet_filter_content_list: todo!() };
                    let mut packet_filter_content_list = Vec::<PacketFilterContent>::new();
                    for i in index..(index + length_packet_filter_contents as usize) - 1 {
                        let filter_content_type = PacketFilterComponentType::from_u8(data[index]);
                        index += 1;
                        let filter_content_value: PacketFilterComponentValue =
                            match filter_content_type {
                                PacketFilterComponentType::MatchAll => {
                                    PacketFilterComponentValue::MatchAll
                                }
                                PacketFilterComponentType::IPv4RemoteAddress => {
                                    let ipv4Address = IPv4FilterAddress {
                                        ipv4_address: data[index..index + 3].to_vec(),
                                        ipv4_address_mask: data[index + 4..index + 7].to_vec(),
                                    };
                                    index += 8;
                                    PacketFilterComponentValue::IPv4RemoteAddress(ipv4Address)
                                }
                                PacketFilterComponentType::IPv4LocalAddress => {
                                    let ipv4Address = IPv4FilterAddress {
                                        ipv4_address: data[index..index + 3].to_vec(),
                                        ipv4_address_mask: data[index + 4..index + 7].to_vec(),
                                    };
                                    index += 8;
                                    PacketFilterComponentValue::IPv4LocalAddress(ipv4Address)
                                }
                                PacketFilterComponentType::IPv6RemoteAddressPrefixLength => {
                                    let ipv6Address = IPv6FilterAddress {
                                        ipv6_address: data[index..index + 15].to_vec(),
                                        prefix_length: data[index + 16],
                                    };
                                    index += 17;
                                    PacketFilterComponentValue::IPv6RemoteAddressPrefixLength(
                                        ipv6Address,
                                    )
                                }
                                PacketFilterComponentType::IPv6LocalAddressPrefixLength => {
                                    let ipv6Address = IPv6FilterAddress {
                                        ipv6_address: data[index..index + 15].to_vec(),
                                        prefix_length: data[index + 16],
                                    };
                                    index += 17;
                                    PacketFilterComponentValue::IPv6LocalAddressPrefixLength(
                                        ipv6Address,
                                    )
                                }
                                PacketFilterComponentType::ProtocolIdentifierNextHeader => {
                                    let buf =
                                        PacketFilterComponentValue::ProtocolIdentifierNextHeader(
                                            ProtocolIdentifierNextHeader { value: data[index] },
                                        );
                                    index += 1;
                                    buf
                                }
                                PacketFilterComponentType::SingleLocalPort => {
                                    let port: u16 =
                                        (data[index] as u16) << 8 | data[index + 1] as u16;
                                    index += 2;
                                    PacketFilterComponentValue::SingleLocalPort(Port {
                                        value: port,
                                    })
                                }
                                PacketFilterComponentType::LocalPortRange => {
                                    let port_low: u16 =
                                        (data[index] as u16) << 8 | data[index + 1] as u16;
                                    let port_high: u16 =
                                        (data[index + 2] as u16) << 8 | data[index + 3] as u16;
                                    index += 4;
                                    PacketFilterComponentValue::LocalPortRange(PortRange {
                                        low: port_low,
                                        high: port_high,
                                    })
                                }
                                PacketFilterComponentType::SingleRemotePort => {
                                    let port: u16 =
                                        (data[index] as u16) << 8 | data[index + 1] as u16;
                                    index += 2;
                                    PacketFilterComponentValue::SingleRemotePort(Port {
                                        value: port,
                                    })
                                }
                                PacketFilterComponentType::RemotePortRange => {
                                    let port_low: u16 =
                                        (data[index] as u16) << 8 | data[index + 1] as u16;
                                    let port_high: u16 =
                                        (data[index + 2] as u16) << 8 | data[index + 3] as u16;
                                    index += 4;
                                    PacketFilterComponentValue::RemotePortRange(PortRange {
                                        low: port_low,
                                        high: port_high,
                                    })
                                }
                                PacketFilterComponentType::SecurityParameterIndex => {
                                    // let para:u32 =  (data[index] as u32) << 24 | data[index + 1] as u16| data[index + 2] as u16| data[index + 3] as u16;
                                    index += 4;
                                    PacketFilterComponentValue::SecurityParameterIndex(
                                        SecurityParameterIndex { value: 0 },
                                    )
                                }
                                PacketFilterComponentType::TypeOfServiceTrafficClass => {
                                    index += 2;
                                    PacketFilterComponentValue::TypeOfServiceTrafficClass(
                                        TypeOfServiceTrafficClass { value: 0, mask: 0 },
                                    )
                                }
                                PacketFilterComponentType::FlowLabel => {
                                    index += 3;
                                    PacketFilterComponentValue::FlowLabel(FlowLabel { value: 0 })
                                }
                                PacketFilterComponentType::DestinationMACAddress => {
                                    index += 6;
                                    PacketFilterComponentValue::DestinationMACAddress(MACAddress {
                                        value: vec![0u8, 0, 0, 0, 0, 0],
                                    })
                                }
                                PacketFilterComponentType::SourceMACAddress => {
                                    index += 6;
                                    PacketFilterComponentValue::SourceMACAddress(MACAddress {
                                        value: vec![0u8, 0, 0, 0, 0, 0],
                                    })
                                }
                                PacketFilterComponentType::VlanCtagVid => {
                                    index += 2;
                                    PacketFilterComponentValue::VlanCtagVid(VlanCtagVid {})
                                }
                                PacketFilterComponentType::VlanStagVid => {
                                    index += 2;
                                    PacketFilterComponentValue::VlanStagVid(VlanStagVid {})
                                }
                                PacketFilterComponentType::VlanCtagPcpdei => {
                                    index += 1;
                                    PacketFilterComponentValue::VlanCtagPcpdei(VlanCtagPcpdei {})
                                }
                                PacketFilterComponentType::VlanStagPcpdei => {
                                    index += 1;
                                    PacketFilterComponentValue::VlanStagPcpdei(VlanStagPcpdei {})
                                }
                                PacketFilterComponentType::Ethertype => {
                                    index += 2;
                                    PacketFilterComponentValue::Ethertype(Ethertype {})
                                }
                                PacketFilterComponentType::DestinationMACAddressRange => {
                                    index += 12;
                                    PacketFilterComponentValue::DestinationMACAddressRange(
                                        DestinationMACAddressRange {},
                                    )
                                }
                                PacketFilterComponentType::SourceMACAddressRange => {
                                    index += 12;
                                    PacketFilterComponentValue::SourceMACAddressRange(
                                        SourceMACAddressRange {},
                                    )
                                }
                            };
                        packet_filter_content_list.push(PacketFilterContent {
                            packet_filter_content_type: filter_content_type,
                            packet_filter_content_value: filter_content_value,
                        });
                    }
                    PacketFilterListEnum::PacketFilterListUpdatePFList(
                        PacketFilterListUpdatePFList {
                            packet_filter_direction: packet_filter_direction,
                            packet_filter_id: packet_filter_id,
                            length_packet_filter_contents: length_packet_filter_contents,
                            packet_filter_content_list: packet_filter_content_list,
                        },
                    )
                }

                _ => PacketFilterListEnum::PacketFilterNone,
            };
            let qosruleprecedence = data[index];
            index += 1;
            let qosflowidentifer = data[index] & 0b00111111;
            let segregation = data[index] & 0b01000000;
            let spare = 0u8;
            index += 1;
            let q_osrules_ie = QOSRulesIE {
                qosruleidentifer,
                lengthof_qo_srule: LengthofQoSrule,
                numberofpacketfilters,
                dqrbit,
                ruleoperationcode,
                packetfilterlist,
                qosruleprecedence,
                qosflowidentifer,
                segregation,
                spare,
            };
            qosRulesIEList.push(q_osrules_ie);
        }
        QOSRules {
            lengthofqosrulesie: length,
            qosrulesie: qosRulesIEList,
        }
    }
}
fn main() {
    let mut pduSessionEstablishmentAcceptMsg = tlv_decode_pdu_session_establishment_accept(vec![
        0x2e, 0x01, 0x01, 0xc2, 0x13, 0x00, 0x09, 0x01, 0x00, 0x06, 0x31, 0x3f, 0x01, 0x01, 0xff,
        0x01, 0x06, 0x06, 0x13, 0x88, 0x04, 0x7a, 0x12, 0x29, 0x0d, 0x03, 0x20, 0x01, 0x04, 0x68,
        0x30, 0x00, 0x00, 0x01, 0xc0, 0xa8, 0x04, 0x02, 0x22, 0x01, 0x01, 0x79, 0x00, 0x06, 0x01,
        0x20, 0x41, 0x01, 0x01, 0x05, 0x7b, 0x00, 0x32, 0x80, 0x80, 0x21, 0x0a, 0x03, 0x00, 0x00,
        0x0a, 0x81, 0x06, 0x08, 0x08, 0x08, 0x08, 0x00, 0x0d, 0x04, 0x08, 0x08, 0x08, 0x08, 0x00,
        0x0c, 0x04, 0xc0, 0xa8, 0x04, 0x01, 0x00, 0x01, 0x10, 0x20, 0x01, 0x04, 0x68, 0x30, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x25, 0x17,
        0x03, 0x69, 0x6d, 0x73, 0x06, 0x6d, 0x6e, 0x63, 0x30, 0x30, 0x31, 0x06, 0x6d, 0x63, 0x63,
        0x30, 0x30, 0x31, 0x04, 0x67, 0x70, 0x72, 0x73,
    ]);

    println!("{:#?}", pduSessionEstablishmentAcceptMsg);
}
