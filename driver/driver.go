package driver

import (
	"encoding/json"
	"fmt"
	"github.com/docker/go-plugins-helpers/network"
	"github.com/vishvananda/netlink"
	"github.com/Tydus/docker-plugin-hostnic/log"
	"io/ioutil"
	"net"
	"os"
	"sync"
)

const (
	networkType         = "hostnic"
	containerVethPrefix = "eth"
	configDir           = "/etc/docker/hostnic"
)

type NicTable map[string]*HostNic

type HostNic struct {
	Name         string // e.g., "en0", "lo0", "eth0.100"
	HardwareAddr string
	Address      string
	AddressIPv6  string
	endpoint     *Endpoint
}

type Endpoint struct {
	id      string
	hostNic *HostNic
	srcName string
	//portMapping []types.PortBinding // Operation port bindings
	dbIndex    uint64
	dbExists   bool
	sandboxKey string
}

func New() (*HostNicDriver, error) {
	err := os.MkdirAll(configDir, os.FileMode(0755))
	if err != nil {
		return nil, err
	}
	d := &HostNicDriver{
		networks: Networks{},
		lock:     sync.RWMutex{},
		nics:     make(NicTable),
	}
	err = d.loadConfig()
	if err != nil {
		return nil, err
	}
	return d, nil
}

type Networks map[string]*Network

type Network struct {
	ID        string
	Gateway4  string
	Gateway6  string
	endpoints map[string]*Endpoint
}

//HostNicDriver implements github.com/docker/go-plugins-helpers/network.Driver
type HostNicDriver struct {
	networks Networks
	nics     NicTable
	lock     sync.RWMutex
}

func (d *HostNicDriver) RegisterNetwork(networkID string, Gateway4 string, Gateway6 string) error {
	if nw := d.getNetworkByGateway(Gateway4); nw != nil {
		return fmt.Errorf("Exist network [%s] has the same ipv4 gateway [%s].", nw.ID, Gateway4)
	}
	if nw := d.getNetworkByGateway(Gateway6); nw != nil {
		return fmt.Errorf("Exist network [%s] has the same ipv6 gateway [%s].", nw.ID, Gateway6)
	}
	nw := Network{
		ID:        networkID,
		Gateway4:  Gateway4,
		Gateway6:  Gateway6,
		endpoints: make(map[string]*Endpoint),
	}
	d.networks[networkID] = &nw
	log.Info("RegisterNetwork [ %s ] Gateway4 : [ %v ] Gateway6 : [ %v ].", nw.ID, nw.Gateway4, nw.Gateway6)
	return nil
}

func (d *HostNicDriver) GetCapabilities() (*network.CapabilitiesResponse, error) {
	return &network.CapabilitiesResponse{Scope: network.LocalScope}, nil
}

func (d *HostNicDriver) CreateNetwork(r *network.CreateNetworkRequest) error {
	log.Debug("CreateNetwork Called: [ %+v ]", r)
	log.Debug("CreateNetwork IPv4Data len : [ %v ], IPv6Data len : [ %v ].", len(r.IPv4Data), len(r.IPv6Data))
	d.lock.Lock()
	defer d.lock.Unlock()
	if r.IPv4Data == nil || len(r.IPv4Data) == 0 {
		return fmt.Errorf("Invalid --gateway parameter.")
	}
	gw4 := net.ParseIP(nw.IPv4Data.Gateway)

	gw6 := nil
	if r.IPv6Data != nil || len(r.IPv4Data) > 0 {
		gw6 = net.ParseIP(nw.IPv6Data.Gateway)
	}
	err := d.RegisterNetwork(r.NetworkID, gw4, gw6)
	if err != nil {
		return err
	}
	d.saveConfig()
	return nil
}

func (d *HostNicDriver) AllocateNetwork(r *network.AllocateNetworkRequest) (*network.AllocateNetworkResponse, error) {
	log.Debug("AllocateNetwork Called: [ %+v ]", r)
	return nil, nil
}

func (d *HostNicDriver) DeleteNetwork(r *network.DeleteNetworkRequest) error {
	log.Debug("DeleteNetwork Called: [ %+v ]", r)
	d.lock.Lock()
	defer d.lock.Unlock()
	delete(d.networks, r.NetworkID)
	d.saveConfig()
	return nil
}
func (d *HostNicDriver) FreeNetwork(r *network.FreeNetworkRequest) error {
	log.Debug("FreeNetwork Called: [ %+v ]", r)
	return nil
}
func (d *HostNicDriver) CreateEndpoint(r *network.CreateEndpointRequest) (*network.CreateEndpointResponse, error) {
	d.lock.Lock()
	defer d.lock.Unlock()

	log.Debug("CreateEndpoint Called: [ %+v ]", r)
	log.Debug("r.Interface: [ %+v ]", r.Interface)
	nw := d.networks[r.NetworkID]

	if nw == nil {
		return nil, fmt.Errorf("Can not find network [ %s ].", r.NetworkID)
	}

	var hostNic *HostNic

	if r.Interface.MacAddress == ""  {
		//Support parameters in driver-opt.
		//It is used when the interface is connected to the container after container has been created.
		r.Interface.MacAddress = r.Options["mac-address"].(string)
	}

	if r.Interface.MacAddress == ""  {
		return nil, fmt.Errorf("Missing --mac-address argument.")
	}

	hostNic = d.FindNicByHardwareAddr(r.Interface.MacAddress)

	if hostNic == nil {
		return nil, fmt.Errorf("Can not find host nic by mac address [ %+v ].", r.Interface.MacAddress)
	}

	if hostNic.endpoint != nil {
		return nil, fmt.Errorf("Host nic [%s] has already bound to endpoint [ %+v ].", hostNic.Name, hostNic.endpoint)
	}

	hostNic.Address = r.Interface.Address
	hostNic.AddressIPv6 = r.Interface.AddressIPv6
	hostIfName := hostNic.Name
	endpoint := &Endpoint{}

	// Store the sandbox side pipe interface parameters
	endpoint.srcName = hostIfName
	endpoint.hostNic = hostNic
	endpoint.id = r.EndpointID

	nw.endpoints[endpoint.id] = endpoint
	hostNic.endpoint = endpoint

	endpointInterface := &network.EndpointInterface{}
	// if r.Interface.Address == "" {
	// 	endpointInterface.Address = hostNic.Address
	// }
	// if r.Interface.AddressIPv6 == "" {
	// 	endpointInterface.AddressIPv6 = hostNic.AddressIPv6
	// }
	// if r.Interface.MacAddress == "" {
	// 	endpointInterface.MacAddress = hostNic.HardwareAddr
	// }
	resp := &network.CreateEndpointResponse{Interface: endpointInterface}
	log.Debug("CreateEndpoint resp interface: [ %+v ] ", resp.Interface)
	return resp, nil
}

func (d *HostNicDriver) EndpointInfo(r *network.InfoRequest) (*network.InfoResponse, error) {
	log.Debug("EndpointInfo Called: [ %+v ]", r)
	d.lock.RLock()
	defer d.lock.RUnlock()
	nw := d.networks[r.NetworkID]
	if nw == nil {
		return nil, fmt.Errorf("Can not find network [ %s ].", r.NetworkID)
	}

	endpoint := nw.endpoints[r.EndpointID]
	if endpoint == nil {
		return nil, fmt.Errorf("Cannot find endpoint [ %s ].", r.EndpointID)
	}

	value := make(map[string]string)
	value["id"] = endpoint.id
	value["srcName"] = endpoint.srcName
	value["hostNic.Name"] = endpoint.hostNic.Name
	value["hostNic.Addr"] = endpoint.hostNic.Address
	value["hostNic.Addrv6"] = endpoint.hostNic.AddressIPv6
	value["hostNic.HardwareAddr"] = endpoint.hostNic.HardwareAddr
	resp := &network.InfoResponse{
		Value: value,
	}
	log.Debug("EndpointInfo resp.Value : [ %+v ]", resp.Value)
	return resp, nil
}
func (d *HostNicDriver) Join(r *network.JoinRequest) (*network.JoinResponse, error) {
	d.lock.Lock()
	defer d.lock.Unlock()
	log.Debug("Join Called: [ %+v ]", r)

	nw := d.networks[r.NetworkID]
	if nw == nil {
		return nil, fmt.Errorf("Can not find network [ %s ].", r.NetworkID)
	}

	endpoint := nw.endpoints[r.EndpointID]
	if endpoint == nil {
		return nil, fmt.Errorf("Cannot find endpoint [ %s ].", r.EndpointID)
	}

	if endpoint.sandboxKey != "" {
		return nil, fmt.Errorf("Endpoint [ %s ] has been bound to sandbox [ %s ]", r.EndpointID, endpoint.sandboxKey)
	}

	endpoint.sandboxKey = r.SandboxKey
	resp := network.JoinResponse{
		InterfaceName:         network.InterfaceName{SrcName: endpoint.srcName, DstPrefix: containerVethPrefix},
		DisableGatewayService: false,
		Gateway:               nw.Gateway4,
		GatewayIPv6:           nw.Gateway6,
	}

	log.Debug("Join resp : [ %+v ]", resp)
	return &resp, nil
}
func (d *HostNicDriver) Leave(r *network.LeaveRequest) error {
	log.Debug("Leave Called: [ %+v ]", r)
	d.lock.Lock()
	defer d.lock.Unlock()

	nw := d.networks[r.NetworkID]
	if nw == nil {
		return fmt.Errorf("Can not find network [ %s ].", r.NetworkID)
	}

	endpoint := nw.endpoints[r.EndpointID]
	if endpoint == nil {
		return fmt.Errorf("Cannot find endpoint [ %s ].", r.EndpointID)
	}

	endpoint.sandboxKey = ""
	return nil
}

func (d *HostNicDriver) DeleteEndpoint(r *network.DeleteEndpointRequest) error {
	log.Debug("DeleteEndpoint Called: [ %+v ]", r)
	d.lock.Lock()
	defer d.lock.Unlock()
	nw := d.networks[r.NetworkID]
	if nw == nil {
		return fmt.Errorf("Can not find network [ %s ].", r.NetworkID)
	}

	endpoint := nw.endpoints[r.EndpointID]
	if endpoint == nil {
		return fmt.Errorf("Cannot find endpoint [ %s ].", r.EndpointID)
	}
	delete(nw.endpoints, r.EndpointID)
	endpoint.hostNic.endpoint = nil
	return nil
}

func (d *HostNicDriver) DiscoverNew(r *network.DiscoveryNotification) error {
	log.Debug("DiscoverNew Called: [ %+v ]", r)
	return nil
}
func (d *HostNicDriver) DiscoverDelete(r *network.DiscoveryNotification) error {
	log.Debug("DiscoverDelete Called: [ %+v ]", r)
	return nil
}
func (d *HostNicDriver) ProgramExternalConnectivity(r *network.ProgramExternalConnectivityRequest) error {
	log.Debug("ProgramExternalConnectivity Called: [ %+v ]", r)
	return nil
}
func (d *HostNicDriver) RevokeExternalConnectivity(r *network.RevokeExternalConnectivityRequest) error {
	log.Debug("RevokeExternalConnectivity Called: [ %+v ]", r)
	return nil
}

func (d *HostNicDriver) getNetworkByGateway(gateway string) *Network {
	for _, nw := range d.networks {
		if nw.Gateway4 == gateway || nw.Gateway6 == gateway {
			return nw
		}
	}
	return nil
}

func (d *HostNicDriver) findNicFromInterfaces(hardwareAddr string) *HostNic {
	nics, err := net.Interfaces()
	if err == nil {
		for _, nic := range nics {
			if nic.HardwareAddr.String() == hardwareAddr {
				return &HostNic{Name: nic.Name, HardwareAddr: nic.HardwareAddr.String()}
			}
		}
	} else {
		log.Error("Get Interfaces error: %s", err.Error())
	}
	return nil
}

func (d *HostNicDriver) findNicFromLinks(hardwareAddr string) *HostNic {
	links, err := netlink.LinkList()
	if err == nil {
		for _, link := range links {
			attr := link.Attrs()
			if attr.HardwareAddr.String() == hardwareAddr {
				return &HostNic{Name: attr.Name, HardwareAddr: attr.HardwareAddr.String()}
			}
		}
	} else {
		log.Error("Get LinkList error: %s", err.Error())
	}
	return nil
}

func (d *HostNicDriver) FindNicByHardwareAddr(hardwareAddr string) *HostNic {
	for _, nic := range d.nics {
		//ensure nic in cache is exist on host.
		if !d.ensureNic(nic) {
			log.Info("Delete nic [%+v] from nic table.", nic)
			delete(d.nics, nic.HardwareAddr)
			continue
		}
		if nic.HardwareAddr == hardwareAddr {
			return nic
		}
	}
	nic := d.findNicFromInterfaces(hardwareAddr)
	if nic == nil {
		nic = d.findNicFromLinks(hardwareAddr)
	}
	if nic != nil {
		log.Info("Add nic [%+v] to nic table.", nic)
		d.nics[nic.HardwareAddr] = nic
	}
	return nic
}

// ensureNic ensure nic exist and info is update
func (d *HostNicDriver) ensureNic(nic *HostNic) bool {
	existNic := d.findNicFromInterfaces(nic.HardwareAddr)
	if existNic == nil {
		existNic = d.findNicFromLinks(nic.HardwareAddr)
	}
	if existNic != nil {
		// nic dev name may be changed by os, so ensure it is update.
		nic.Name = existNic.Name
	}
	return existNic != nil
}

func (d *HostNicDriver) loadConfig() error {
	configFile := fmt.Sprintf("%s/%s", configDir, "config.json")
	exists, err := FileExists(configFile)
	if err != nil {
		return err
	}
	if exists {
		configData, err := ioutil.ReadFile(configFile)
		if err != nil {
			return err
		}
		networks := Networks{}
		err = json.Unmarshal(configData, &networks)
		if err != nil {
			return err
		}
		log.Info("Load config from [%s].", configFile)
		for _, nw := range networks {
			d.RegisterNetwork(nw.ID, nw.IPv4Data)
		}
	}
	return nil
}

//write driver network to file, wait docker 1.3 to support plugin data persistence.
func (d *HostNicDriver) saveConfig() error {
	configFile := fmt.Sprintf("%s/%s", configDir, "config.json")
	data, err := json.Marshal(d.networks)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(configFile, data, os.FileMode(0644))
	if err != nil {
		return err
	}
	log.Debug("Save config [%+v] to [%s].", d.networks, configFile)
	return nil
}
