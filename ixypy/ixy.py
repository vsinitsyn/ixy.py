from abc import ABC, abstractmethod


class IxyDevice(ABC):
    def __init__(self, pci_device, num_rx_queues=1, num_tx_queues=1):
        self.pci_device = pci_device
        self.num_rx_queues = num_rx_queues
        self.num_tx_queues = num_tx_queues
        self._initialize_device()

    @abstractmethod
    def _initialize_device(self):
        pass

    @abstractmethod
    def get_link_speed(self):
        pass

    @abstractmethod
    def set_promisc(self):
        pass

    @abstractmethod
    def get_stats(self):
        pass

    @abstractmethod
    def tx_batch(self):
        pass

    @abstractmethod
    def rx_batch(self):
        pass
