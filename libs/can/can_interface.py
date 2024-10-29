from abc import ABC, abstractmethod


class CanInterface(ABC):
    @abstractmethod
    def connect(self):
        """建立CAN总线的连接"""
        pass

    @abstractmethod
    def close(self):
        """关闭CAN接口连接"""
        pass

    @abstractmethod
    def send(self, arb_id, data, is_extended=None, is_error=False, is_remote=False, is_fd=False, channel=0):
        """
        发送CAN消息

        :return:
        """
        pass

    @abstractmethod
    def recv(self, channel, timeout=None):
        """
        接收CAN消息

        :return: 返回接收到的消息元组 (message_id, data, timestamp)
        """
        pass

    def set_filters(self, filters):
        """
        设置过滤器
        :param filters: 过滤器
        :return:
        """
        pass

    def clear_filters(self):
        """
        清除过滤器
        :return:
        """
        pass
