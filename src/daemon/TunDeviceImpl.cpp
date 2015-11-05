/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "TunDeviceImpl.h"

#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

using namespace hipdex_vpn;

TunDeviceImpl::TunDeviceImpl()
	: m_fd(-1), m_sockfd(-1)
{
	memset(&m_ifr, 0, sizeof(m_ifr));
	memset(&m_ifr6, 0, sizeof(m_ifr6));
}

TunDeviceImpl::~TunDeviceImpl()
{
	if (m_fd != -1)
		close(m_fd);

	if (m_sockfd != -1)
		close(m_sockfd);
}

bool TunDeviceImpl::CreateDevice(const std::string& name)
{
	if ((m_fd = open("/dev/net/tun", O_RDWR)) < 0)
		return false;

	m_ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(m_ifr.ifr_name, name.c_str(), IFNAMSIZ);

	if ((ioctl(m_fd, TUNSETIFF, &m_ifr)) < 0)
		return false;

	if ((m_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return false;

	return true;
}

bool TunDeviceImpl::SetIpv6Addr(const std::string& addr, int prefixLen)
{
	int sockfd;
	ifreq ifr;

	memset(&ifr, 0, sizeof(ifreq));
	in6_ifreq* ifr6 = (in6_ifreq*)&ifr;

	if (ioctl(m_sockfd, SIOGIFINDEX, &m_ifr) < 0)
		return false;

	if (inet_pton(AF_INET6, addr.c_str(), &ifr6->ifr6_addr) < 1)
		return false;

	ifr6->ifr6_ifindex = m_ifr.ifr_ifindex;
	ifr6->ifr6_prefixlen = prefixLen;

	if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		return false;

	if (ioctl(sockfd, SIOCSIFADDR, ifr6) < 0) {
		close(sockfd);
		return false;
	}

	memcpy(&m_ifr6, ifr6, sizeof(in6_ifreq));

	close(sockfd);
	return true;
}

bool TunDeviceImpl::SetIpv4Addr(const std::string& addr)
{
	sockaddr_in sai;
	memset(&sai, 0, sizeof(sockaddr));

	sai.sin_family = AF_INET;

	if (inet_pton(AF_INET, addr.c_str(), &sai.sin_addr) < 1)
		return false;

	memcpy(&m_ifr.ifr_addr, &sai, sizeof(sockaddr));

	if (ioctl(m_sockfd, SIOCSIFADDR, &m_ifr) < 0)
		return false;

	return true;
}

bool TunDeviceImpl::SetIpv4Netmask(const std::string& addr)
{
	sockaddr_in sai;
	memset(&sai, 0, sizeof(sockaddr));

	sai.sin_family = AF_INET;

	if (inet_pton(AF_INET, addr.c_str(), &sai.sin_addr) < 1)
		return false;

	memcpy(&m_ifr.ifr_addr, &sai, sizeof(sockaddr));

	if (ioctl(m_sockfd, SIOCSIFNETMASK, &m_ifr) < 0)
		return false;

	return true;
}

bool TunDeviceImpl::SetMtu(int value)
{
	m_ifr.ifr_mtu = value;

	if (ioctl(m_sockfd, SIOCSIFMTU, &m_ifr) < 0)
		return false;

	return true;
}

bool TunDeviceImpl::BringUp()
{
	if (ioctl(m_sockfd, SIOCSIFFLAGS, &m_ifr) < 0)
		return false;

	m_ifr.ifr_flags |= IFF_UP;
	m_ifr.ifr_flags |= IFF_RUNNING;
	m_ifr.ifr_flags &= ~IFF_NOARP;
	m_ifr.ifr_flags &= ~ IFF_NOTRAILERS;

	if (ioctl(m_sockfd, SIOCSIFFLAGS, &m_ifr) < 0)
		return false;

	return true;
}
