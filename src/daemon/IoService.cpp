/*
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "IoService.h"

#include <thread>
#include <memory>
#include <vector>

#include <boost/bind.hpp>

using namespace hipdex_vpn;

IoService::IoService(std::size_t numThreads)
	: m_service(), m_signals(m_service),
	  m_numThreads(numThreads)
{
	m_signals.add(SIGINT);
	m_signals.add(SIGTERM);
	m_signals.add(SIGQUIT);
	m_signals.add(SIGHUP);

	m_signals.async_wait(boost::bind(
		&IoService::StopService, this));
}

IoService::~IoService()
{
}

void IoService::Run()
{
	std::vector<std::shared_ptr<std::thread>> threads;
	threads.reserve(m_numThreads);

	for (std::size_t i = 0; i < m_numThreads; ++i)
		threads.push_back(std::make_shared<std::thread>
			(&IoService::RunService, this));

	for (auto& thread : threads)
			thread->join();
}

void IoService::RunService()
{
	m_service.run();
}

void IoService::StopService()
{
	m_service.stop();
}
