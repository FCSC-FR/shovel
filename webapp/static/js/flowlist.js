'use strict'

/*
 * Copyright (C) 2023-2024  ANSSI
 * Copyright (C) 2025  A. Iooss
 * Copyright (C) 2025  D. Mazzini
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

import Api from './api.js'

const DATE_PARAMS = { hour: 'numeric', minute: 'numeric', second: 'numeric', fractionalSecondDigits: 1 }

/**
 * Flow list sidebar
 *
 * Triggers 'locationchange' event on the window to update flow display.
 */
class FlowList {
  constructor () {
    this.apiClient = new Api()
    const url = new URL(document.location)
    this.selectedFlowId = url.searchParams.get('flow')
  }

  async init () {
    // Handle left arrow, right arrow and escape keys to navigate flows
    // Handle CTRL-MAJ-F key to search selection
    document.addEventListener('keydown', e => {
      if (e.target.tagName === 'INPUT' || e.altKey) {
        return // Don't overwrite keys on input or when pressing ALT
      }
      if (!e.ctrlKey && !e.shiftKey && e.code === 'ArrowLeft') {
        if (this.selectedFlowId) {
          let prevElem = document.querySelector('#flow-list a.active')?.previousElementSibling
          if (prevElem && prevElem.tagName.toLowerCase() === 'span') {
            prevElem = prevElem.previousElementSibling
          }
          prevElem?.click()
        } else {
          document.querySelector('#flow-list a')?.click()
        }
        e.preventDefault()
      } else if (!e.ctrlKey && !e.shiftKey && e.code === 'ArrowRight') {
        if (this.selectedFlowId) {
          let nextElem = document.querySelector('#flow-list a.active')?.nextElementSibling
          if (nextElem && nextElem.tagName.toLowerCase() === 'span') {
            nextElem = nextElem.nextElementSibling
          }
          nextElem?.click()
        } else {
          document.querySelector('#flow-list a')?.click()
        }
        e.preventDefault()
      } else if (!e.ctrlKey && !e.shiftKey && e.code === 'Escape' && this.selectedFlowId !== null) {
        this.selectedFlowId = null
        window.history.pushState(null, '', window.location.pathname)
        window.dispatchEvent(new Event('locationchange'))
        e.preventDefault()
      } else if (e.ctrlKey && e.shiftKey && e.code === 'KeyF') {
        const sel = window.getSelection().toString()
        if (sel) {
          const url = new URL(document.location)
          url.searchParams.set('search', sel)
          window.history.pushState(null, '', url.href)
          this.updateFlowsList()
        }
        e.preventDefault()
      }
    })

    // On flow click, update URL and dispatch 'locationchange' event
    document.getElementById('flow-list').addEventListener('click', e => {
      if (!e.ctrlKey) {
        const newFlowId = e.target.closest('a')?.dataset?.flow
        if (newFlowId && this.selectedFlowId !== newFlowId) {
          this.selectedFlowId = newFlowId
          window.history.pushState(null, '', e.target.closest('a').href)
          window.dispatchEvent(new Event('locationchange'))
        }
        e.preventDefault()
      }
    })

    // On flows list scroll, update timeline indicator
    document.getElementById('flow-list').parentElement.addEventListener('scroll', e => {
      this.updateTimeline()
    })

    // Infinite scroll: load more flows when loading indicator is seen
    this.observer = new window.IntersectionObserver((entries) => {
      entries.forEach(async e => {
        if (e.isIntersecting) {
          const lastFlowTs = document.getElementById('flow-list').lastElementChild?.dataset.ts_start
          if (lastFlowTs) {
            // User sees loading indicator and flows list is not empty
            await this.updateFlowsList(lastFlowTs)
          }
        }
      })
    })
    this.observer.observe(document.getElementById('flow-list-loading-indicator'))

    // On browser history pop, dispatch 'locationchange' event, then update flows list
    window.addEventListener('popstate', async () => {
      const url = new URL(document.location)
      const newFlowId = url.searchParams.get('flow')
      if (this.selectedFlowId !== newFlowId) {
        this.selectedFlowId = newFlowId
        window.dispatchEvent(new Event('locationchange'))
      }
      await this.updateFlowsList()
    })

    // On 'locationchange' event, update active flow
    window.addEventListener('locationchange', _ => {
      this.updateActiveFlow(true)
    })

    // On services filter change, update URL then update flows list
    document.getElementById('services-select').addEventListener('change', e => {
      const url = new URL(document.location)
      url.searchParams.delete('service')
      e.target.value.split(',').forEach(s => {
        if (s) {
          url.searchParams.append('service', s)
        }
      })
      window.history.pushState(null, '', url.href)
      this.updateFlowsList()
    })

    // Don't close filter dropdown on click inside
    document.getElementById('dropdown-filter').addEventListener('click', e => {
      e.stopPropagation()
    })

    // On time filter change, update URL then update flows list
    document.getElementById('filter-time-until').addEventListener('change', e => {
      const untilTick = Number(e.target.value)
      const url = new URL(document.location)
      if (untilTick) {
        url.searchParams.set('to', Math.floor(((untilTick + 1) * (this.tickLength || 1) + this.timestampStart / 1000000)) * 1000000)
      } else {
        url.searchParams.delete('to')
        e.target.value = null
      }
      window.history.pushState(null, '', url.href)
      this.updateFlowsList()
    })

    // On protocol filter change, update URL then update flows list
    document.getElementById('filter-protocol').addEventListener('change', e => {
      const appProto = e.target.value
      const url = new URL(document.location)
      if (appProto) {
        url.searchParams.set('app_proto', appProto)
      } else {
        url.searchParams.delete('app_proto')
      }
      window.history.pushState(null, '', url.href)
      this.updateFlowsList()
    })

    // On glob search filter submit, update URL then update flows list
    document.getElementById('filter-search').addEventListener('keyup', e => {
      if (e.key !== 'Enter') {
        return
      }
      const search = e.target.value
      const url = new URL(document.location)
      if (search) {
        url.searchParams.set('search', search)
      } else {
        url.searchParams.delete('search')
      }
      window.history.pushState(null, '', url.href)
      this.updateFlowsList()
    })

    // On tags filter change, update URL then update flows list
    document.getElementById('filter-tag').addEventListener('click', e => {
      const tag = e.target.closest('a')?.dataset.tag
      if (tag) {
        const url = new URL(document.location)
        const requiredTags = url.searchParams.getAll('tag_require')
        const deniedTags = url.searchParams.getAll('tag_deny')
        if (requiredTags.includes(tag)) {
          // Remove tag from required tags
          url.searchParams.delete('tag_require')
          requiredTags.forEach(t => {
            if (t !== tag) {
              url.searchParams.append('tag_require', t)
            }
          })
          // If shift is pressed, then add to denied tags
          if (e.shiftKey) {
            url.searchParams.append('tag_deny', tag)
          }
        } else if (deniedTags.includes(tag)) {
          // Remove tag from denied tags
          url.searchParams.delete('tag_deny')
          deniedTags.forEach(t => {
            if (t !== tag) {
              url.searchParams.append('tag_deny', t)
            }
          })
          // If shift is pressed, then add to required tags
          if (e.shiftKey) {
            url.searchParams.append('tag_require', tag)
          }
        } else if (e.shiftKey) {
          // Add tag to denied tags
          url.searchParams.append('tag_deny', tag)
        } else {
          // Add tag to required tags
          url.searchParams.append('tag_require', tag)
        }
        window.history.pushState(null, '', url.href)
        this.updateFlowsList()
        e.preventDefault()
      }
    })

    document.getElementById('timeline').addEventListener('click', e => {
      const position = (e.layerY / e.target.clientHeight)
      const tsTop = Math.floor(this.timestampMax - position * (this.timestampMax - this.timestampMin))
      if (tsTop) {
        const url = new URL(document.location)
        url.searchParams.set('to', tsTop)
        window.history.pushState(null, '', url.href)
        this.updateFlowsList()
      }
    })

    document.getElementById('timeline').addEventListener('mousemove', e => {
      // Bottom margin of 30px and offset of 5px
      const mousePosition = e.pageY - 5
      const tooltipTop = Math.min(e.pageY - 5, document.getElementById('timeline').clientHeight - 30)
      document.querySelector('#timeline .tooltip').style.top = `${tooltipTop}px`
      const position = (mousePosition / document.getElementById('timeline').clientHeight)
      const tsTop = Math.floor(this.timestampMax - position * (this.timestampMax - this.timestampMin))
      if (tsTop) {
        const dateStart = new Date(tsTop / 1000)
        let text = (this.tickLength > 0) ? `Tick ${Math.floor((tsTop - this.timestampStart) / 1000000 / this.tickLength)}, ` : ''
        text += new Intl.DateTimeFormat(undefined, DATE_PARAMS).format(dateStart)
        document.querySelector('#timeline .tooltip .tooltip-inner').textContent = text
      }
    })

    // Apply current flow tick as time filter on click
    document.querySelector('#display-flow-tick > a').addEventListener('click', e => {
      const url = new URL(document.location)
      url.searchParams.set('to', e.currentTarget.dataset.ts)
      window.history.pushState(null, '', url.href)
      this.updateFlowsList()
    })

    // State updated using API status endpoint
    this.timestampMin = 0  // first flow in database
    this.timestampMax = 0  // last flow in database
    this.timestampStart = 0  // game start
    this.tickLength = 0
    this.services = {}
    this.appProto = []
    this.tags = []

    this.updateServiceFilter()
    await this.updateStatus()
    await this.updateFlowsList()
  }

  /**
   * Pretty print delay
   * @param {Number} delay Delay in milliseconds
   * @returns Pretty string representation
   */
  pprintDelay (delay) {
    delay = delay / 1000
    if (delay > 1000) {
      delay = delay / 1000
      return `${delay.toPrecision(3)} s`
    } else {
      return `${delay.toPrecision(3)} ms`
    }
  }

  /**
   * Pretty print service IP address and port using Shovel configuration
   * @param {String} destIp
   * @param {Number} destPort
   * @returns Pretty string representation
   */
  pprintService (destIp, destPort) {
    const ipport = destIp + (destPort ? `:${destPort}` : '')
    const name = Object.keys(this.services).find(name => this.services[name].includes(ipport))
    return name ? `${name} (:${destPort})` : ipport
  }

  /**
   * Build tag element
   * @param {String} text Tag name
   * @param {String} color Tag color
   * @param {Number} count Tag count
   * @returns HTML element representing the tag
   */
  tagBadge (text, color, count) {
    const badge = document.createElement('span')
    badge.classList.add('badge', `text-bg-${color ?? 'none'}`, 'mb-1', 'me-1', 'p-1')
    badge.textContent = text
    if (count !== undefined) {
      const badgeCount = document.createElement('span')
      badgeCount.classList.add('text-bg-dark', 'bg-opacity-75', 'rounded', 'me-1', 'px-1')
      badgeCount.textContent = count
      badge.prepend(badgeCount)
    }
    return badge
  }

  updateTimeline () {
    const visibleFlows = [...document.querySelectorAll('#flow-list > a')].filter(e => {
      const rect = e.getBoundingClientRect()
      return rect.bottom >= 0 && rect.top <= window.innerHeight
    })
    const tsTop = visibleFlows[0]?.dataset?.ts_start
    const tsBottom = visibleFlows[visibleFlows.length - 1]?.dataset?.ts_start

    // Update indicator size and position
    const size = Math.max((tsTop - tsBottom) / (this.timestampMax - this.timestampMin), 0.005)
    const position = (this.timestampMax - tsTop) / (this.timestampMax - this.timestampMin)
    document.getElementById('timeline-indicator').style.height = `${size * 100}%`
    document.getElementById('timeline-indicator').style.top = `${position * 100}%`

    // Update game start bar
    if (this.timestampMin < this.timestampStart && this.timestampStart < this.timestampMax) {
      const positionGameStart = (this.timestampMax - this.timestampStart) / (this.timestampMax - this.timestampMin)
      document.getElementById('timeline-game-start').classList.toggle('d-none', this.timestampStart === 0)
      document.getElementById('timeline-game-start').style.height = `3px`
      document.getElementById('timeline-game-start').style.top = `${positionGameStart * 100}%`
    }
  }

  /**
   * Update services in filters select
   */
  updateServiceFilter () {
    const serviceSelect = document.getElementById('services-select')

    // Empty options
    while (serviceSelect.lastChild) {
      serviceSelect.removeChild(serviceSelect.lastChild)
    }

    // Fill options
    const allFlowsOptionEl = document.createElement('option')
    allFlowsOptionEl.value = ''
    allFlowsOptionEl.textContent = 'All flows'
    serviceSelect.appendChild(allFlowsOptionEl)

    const unknownSrvOptionEl = document.createElement('option')
    unknownSrvOptionEl.value = '!'
    unknownSrvOptionEl.textContent = 'Flows from unknown services'
    serviceSelect.appendChild(unknownSrvOptionEl)

    for (const [name, ipAddrPorts] of Object.entries(this.services)) {
      const optgroupEl = document.createElement('optgroup')
      optgroupEl.label = name
      if (ipAddrPorts.length > 1) {
        const optionEl = document.createElement('option')
        optionEl.value = ipAddrPorts
        optionEl.textContent = `All (${name})`
        optgroupEl.appendChild(optionEl)
      }
      ipAddrPorts.forEach(addrPort => {
        const optionEl = document.createElement('option')
        optionEl.value = addrPort
        optionEl.textContent = `${addrPort} (${name})`
        optgroupEl.appendChild(optionEl)
      })
      serviceSelect.appendChild(optgroupEl)
    }

    // Update service filter state
    const url = new URL(document.location)
    const chosenService = url.searchParams.getAll('service').join(',')
    serviceSelect.value = chosenService
  }

  /**
   * Update protocols in filters dropdown
   */
  updateProtocolFilter (appProto) {
    const protocolSelect = document.getElementById('filter-protocol')

    // Empty select options
    while (protocolSelect.lastChild) {
      protocolSelect.removeChild(protocolSelect.lastChild)
    }

    // Add protocols
    let option = document.createElement('option')
    option.value = ''
    option.textContent = 'All'
    protocolSelect.appendChild(option)
    option = document.createElement('option')
    option.value = 'raw'
    option.textContent = 'Raw'
    protocolSelect.appendChild(option)
    appProto.forEach((proto) => {
      const option = document.createElement('option')
      option.value = proto
      option.textContent = proto.toUpperCase()
      protocolSelect.appendChild(option)
    })

    // Update protocol filter select state
    const url = new URL(document.location)
    const current = url.searchParams.get('app_proto')
    protocolSelect.value = current ?? ''
    protocolSelect.classList.toggle('is-active', current !== null)
  }

  /**
   * Update tags in filters dropdown
   * @param {Array} tags All available tags
   * @param {Array} requiredTags Required tags in filter
   * @param {Array} deniedTags Denied tags in filter
   */
  updateTagFilter (tags, requiredTags, deniedTags) {
    // Empty dropdown content
    ['filter-tag-available', 'filter-tag-require', 'filter-tag-deny'].forEach(id => {
      const el = document.getElementById(id)
      el.parentElement.classList.add('d-none')
      while (el.lastChild) {
        el.removeChild(el.lastChild)
      }
    })

    // Create tags and append to corresponding section of dropdown
    tags.forEach(t => {
      const { tag, color } = t
      const badge = this.tagBadge(tag, color)
      const link = document.createElement('a')
      link.href = '#'
      link.dataset.tag = tag
      link.appendChild(badge)
      let destElement = document.getElementById('filter-tag-available')
      if (requiredTags.includes(tag)) {
        destElement = document.getElementById('filter-tag-require')
      } else if (deniedTags.includes(tag)) {
        destElement = document.getElementById('filter-tag-deny')
      }
      destElement.appendChild(link)
      destElement.parentElement.classList.remove('d-none')
    })
  }

  /**
   * Fill flows list using given flows
   */
  fillFlowsList (flows) {
    const flowList = document.getElementById('flow-list')
    flows.forEach((flow) => {
      const date = new Date(flow.ts_start / 1000)
      const startDate = new Intl.DateTimeFormat(undefined, DATE_PARAMS).format(date)

      // Don't insert flow already in list
      // This happens when adding flows during infinite scroll
      if (flowList.querySelector(`a[data-flow="${flow.id}"]`)) {
        return
      }

      // Create tick element on new tick
      if (this.tickLength > 0) {
        const tick = Math.floor((flow.ts_start - this.timestampStart) / 1000000 / this.tickLength)
        if (tick !== this.lastTick) {
          const tickEl = document.createElement('span')
          tickEl.classList.add('list-group-item', 'sticky-top', 'pt-3', 'pb-1', 'px-2', 'border-0', 'border-bottom', 'bg-light-subtle', 'text-center', 'fw-semibold')
          tickEl.textContent = `Tick ${tick}`
          flowList.appendChild(tickEl)
          this.lastTick = tick
        }
      }

      // Build URL
      const url = new URL(document.location)
      url.searchParams.set('flow', flow.id)

      // Build DOM elements
      const flowEl = document.createElement('a')
      flowEl.classList.add('list-group-item', 'list-group-item-action', 'py-1', 'px-2', 'lh-sm', 'border-0', 'border-bottom')
      flowEl.href = url.href
      flowEl.dataset.flow = flow.id
      flowEl.dataset.ts_start = flow.ts_start

      const flowInfoDiv = document.createElement('div')
      flowInfoDiv.classList.add('d-flex', 'justify-content-between', 'mb-1')
      const flowInfoDiv1 = document.createElement('small')
      flowInfoDiv1.textContent = this.pprintService(flow.dest_ip, flow.dest_port)
      const flowInfoDiv2 = document.createElement('small')
      flowInfoDiv2.textContent = `${this.pprintDelay(flow.ts_end - flow.ts_start)}, ${startDate}`
      flowInfoDiv.appendChild(flowInfoDiv1)
      flowInfoDiv.appendChild(flowInfoDiv2)
      flowEl.appendChild(flowInfoDiv)

      // Use application protocol as first badge if defined
      const appProto = flow.app_proto?.replace('failed', 'raw') ?? 'raw'
      const badge = this.tagBadge(appProto.toUpperCase())
      flowEl.appendChild(badge)

      const flowTags = flow.tags?.split(',')
      this.tags.forEach(t => {
        const { tag, color } = t
        if (flowTags?.includes(tag)) {
          const tagId = 'tag_' + tag.replace(/[^A-Za-z0-9]/g, '_')
          const badge = this.tagBadge(tag, color, flow.flowints?.[tagId])
          flowEl.appendChild(badge)
        }
      })

      flowList.appendChild(flowEl)
    })

    // Hide loading indicator if we are displaying less than 100 new flows
    document.getElementById('flow-list-loading-indicator').classList.toggle('d-none', flows.length < 99)

    // Update timeline with new visible flows
    this.updateTimeline()

    // Refresh observer
    // This trigger the observer again if the loading indicator is still intersecting with the viewport
    this.observer.disconnect()
    this.observer.observe(document.getElementById('flow-list-loading-indicator'))
  }

  /**
   * Update highlighted flow in flows list
   */
  updateActiveFlow (scrollInto) {
    document.querySelector('#flow-list a.active')?.classList.remove('active')
    const linkElement = document.querySelector(`#flow-list a[data-flow="${this.selectedFlowId}"]`)
    linkElement?.classList.add('active')
    if (scrollInto) {
      linkElement?.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' })
    }
  }

  /**
   * Query API status endpoint and update timeline
   */
  async updateStatus () {
    // Fetch API and show toast notification if cannot be reached
    let apiStatus = null
    try {
      apiStatus = await this.apiClient.getStatus()
    } catch (error) {}
    setTimeout(this.updateStatus.bind(this), 1000)
    document.getElementById('toast-offline').classList.toggle('show', apiStatus === null)
    if (apiStatus === null) {
      return
    }
    const { timestampMin, timestampMax, config, appProto, tags } = apiStatus

    // Update game timestamps
    const timestampStart = Math.floor(Date.parse(config.start_date) * 1000)
    if (this.timestampMin !== timestampMin || this.timestampMax !== timestampMax || this.timestampStart !== timestampStart) {
      this.timestampMin = timestampMin
      this.timestampMax = timestampMax
      this.timestampStart = timestampStart
      this.updateTimeline()
    }

    // Update tick length
    if (this.tickLength !== config.tick_length) {
      this.tickLength = config.tick_length
      await this.updateFlowsList()
    }

    // Update services choice
    if (JSON.stringify(this.services) !== JSON.stringify(config.services)) {
      this.services = config.services
      this.updateServiceFilter(config.services)
    }

    // Update application protocols choice
    if (JSON.stringify(this.appProto) !== JSON.stringify(appProto)) {
      this.appProto = appProto
      this.updateProtocolFilter(appProto)
    }

    // Update tags choice
    if (JSON.stringify(this.tags) !== JSON.stringify(tags)) {
      this.tags = tags
      const url = new URL(document.location)
      const filterTagsRequire = url.searchParams.getAll('tag_require')
      const filterTagsDeny = url.searchParams.getAll('tag_deny')
      this.updateTagFilter(tags, filterTagsRequire, filterTagsDeny)
    }
  }

  /**
   * Query API and update flows list
   * If `fillTo` is given, then only append newly fetch flows
   */
  async updateFlowsList (fillTo) {
    const url = new URL(document.location)
    const fromTs = url.searchParams.get('from')
    const toTs = fillTo ?? url.searchParams.get('to')
    const services = url.searchParams.getAll('service')
    const filterAppProto = url.searchParams.get('app_proto')
    const filterSearch = url.searchParams.get('search')
    const filterTagsRequire = url.searchParams.getAll('tag_require')
    const filterTagsDeny = url.searchParams.getAll('tag_deny')

    if (!fillTo) {
      // Update search input
      const searchInput = document.getElementById('filter-search')
      searchInput.value = filterSearch ?? ''
      searchInput.classList.toggle('is-active', filterSearch !== null)

      // Update filter dropdown visual indicator
      document.querySelector('#dropdown-filter > button').classList.toggle('text-bg-purple', toTs || filterTagsRequire.length || filterTagsDeny.length || filterAppProto || filterSearch)

      // Update time filter state
      if (toTs) {
        const toTick = (Number(toTs) - this.timestampStart) / 1000000 / (this.tickLength || 1) - 1
        document.getElementById('filter-time-until').value = toTick
      }
      document.getElementById('filter-time-until').classList.toggle('is-active', toTs)

      // Update tags filter before API response
      this.updateTagFilter(this.tags, filterTagsRequire, filterTagsDeny)

      // Empty flow list
      const flowList = document.getElementById('flow-list')
      while (flowList.lastChild) {
        flowList.removeChild(flowList.lastChild)
      }
      this.lastTick = null

      // Show loading indicator
      // As the list is empty, the infinite scroll callback won't be triggered
      document.getElementById('flow-list-loading-indicator').classList.remove('d-none')
    }

    // Fetch API and update
    const { flows } = await this.apiClient.listFlows(
      fromTs ? Number(fromTs) : null,
      toTs ? Number(toTs) : null,
      services,
      filterAppProto,
      filterSearch,
      filterTagsRequire,
      filterTagsDeny
    )
    this.fillFlowsList(flows)
    this.updateActiveFlow(!fillTo)
  }
}

const flowList = new FlowList()
flowList.init()
