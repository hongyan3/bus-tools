from xml.dom import minidom

class Sddb:
    """
    Sddb file parser
    """
    def __init__(self, filename: str):
        print('[info] loading sddb file ...')
        self.doc = minidom.parse(filename)
        print('[info] load file success.')
    
    def get_ecus(self) -> set:
        """
        获取ECU_NAME -> ECU_ADDRESS 字典
        """
        if self.doc is None:
            raise ValueError('sddb file not loaded.')
        list = set()
        ecus = self.doc.getElementsByTagName('ECU')
        tmp_arr = [int(i.getAttribute('address'), 16) for i in ecus]
        list.update(tmp_arr)
        return list
    
    def get_services(self, ecu_address: int) -> set:
        """
        获取ECU的服务
        """
        list = set()
        ecu_address = hex(ecu_address)[2:].upper()
        ecus = self.doc.getElementsByTagName('ECU')
        for ecu in ecus:
            if ecu.getAttribute('address') == ecu_address:
                services = ecu.getElementsByTagName('Service')
                temp_arr = [int(i.getAttribute('ID'), 16) for i in services]
                list.update(temp_arr)
        return list

    def get_dids(self, ecu_address: int) -> set:
        list = set()
        ecu_address = hex(ecu_address)[2:].upper()
        ecus = self.doc.getElementsByTagName('ECU')
        for ecu in ecus:
            if ecu.getAttribute('address') == ecu_address:
                dids = ecu.getElementsByTagName('DataIdentifier')
                temp_arr = [int(i.getAttribute('ID'), 16) for i in dids]
                list.update(temp_arr)
        return list
    
    def get_subfunctions(self, ecu_address: int, service_id: int) -> set:
        """
        根据ecu地址和服务id获取子服务列表
        """
        list = set()
        ecu_address = hex(ecu_address)[2:].upper()
        ecus = self.doc.getElementsByTagName('ECU')
        for ecu in ecus:
            if ecu.getAttribute('address') == ecu_address:
                services = ecu.getElementsByTagName('Service')
                for service in services:
                    if int(service.getAttribute('ID'), 16) == service_id:
                        subfunctions = service.getElementsByTagName('Subfunction')
                        temp_arr = [int(i.getAttribute('ID'), 16) for i in subfunctions]
                        list.update(temp_arr)
        return list