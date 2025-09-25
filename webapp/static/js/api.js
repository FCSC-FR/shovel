'use strict'
/* global location, EventSource */

/*
 * Copyright (C) 2023-2024  ANSSI
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * API client
 */
export default class Api {
  /**
   * Call API to get flows, application protocols list
   *
   * API limits results to 100 entries.
   *
   * @param {Number} timestampFrom Keep only flows after this timestamp
   * @param {Number} timestampTo Keep only flows before this timestamp
   * @param {Array} services Keep only flows matching these IP address and ports
   * @param {String} appProto Keep only flows matching this app-layer protocol
   * @param {String} search Search for this glob pattern in flows payloads
   * @param {Array} tagsRequire Keep only flows matching these tags
   * @param {Array} tagsDeny Deny flows matching these tags
   */
  async listFlows (timestampFrom, timestampTo, services, appProto, search, tagsRequire, tagsDeny) {
    const url = new URL(`${location.origin}${location.pathname}api/flow`)
    if (typeof timestampFrom === 'number') {
      url.searchParams.append('from', timestampFrom)
    }
    if (typeof timestampTo === 'number') {
      url.searchParams.append('to', timestampTo)
    }
    services?.forEach((s) => {
      url.searchParams.append('service', s)
    })
    if (appProto) {
      url.searchParams.append('app_proto', appProto)
    }
    if (search) {
      url.searchParams.append('search', search)
    }
    tagsRequire?.forEach((t) => {
      url.searchParams.append('tag_require', t)
    })
    tagsDeny?.forEach((t) => {
      url.searchParams.append('tag_deny', t)
    })
    const response = await fetch(url.href, {})
    if (!response.ok) {
      throw Error('failed to list flows')
    }

    const data = await response.json()
    return data
  }

  /**
   * Call API to get flow details from identifier
   *
   * @param {Number} flowId Flow identifier
   */
  async getFlow (flowId) {
    const response = await fetch(`api/flow/${flowId}`, {})
    if (!response.ok) {
      return null
    }

    const data = await response.json()
    return data
  }

  /**
   * Call API to get flow raw data from identifier
   *
   * @param {Number} flowId Flow identifier
   */
  async getFlowRaw (flowId) {
    const response = await fetch(`api/flow/${flowId}/raw`, {})
    if (!response.ok) {
      throw Error('failed to get flow raw data')
    }

    const data = await response.json()
    return data
  }

  /**
   * Setup server-sent events handler
   *
   * @param {CallableFunction} offlineCallback Function called to indicate backend status
   * @param {CallableFunction} configCallback Function called on new server config
   * @param {CallableFunction} timestampMinMaxCallback Function called on new timestamps
   * @param {CallableFunction} appProtoCallback Function called on new app protocols
   * @param {CallableFunction} tagsCallback Function called on new tags
   */
  subscribeEvents (offlineCallback, configCallback, timestampMinMaxCallback, appProtoCallback, tagsCallback) {
    const evtSource = new EventSource('api/events')
    evtSource.addEventListener('config', e => {
      offlineCallback(false)
      configCallback(JSON.parse(e.data))
    })
    evtSource.addEventListener('timestampMinMax', e => timestampMinMaxCallback(JSON.parse(e.data)))
    evtSource.addEventListener('appProto', e => appProtoCallback(JSON.parse(e.data)))
    evtSource.addEventListener('tags', e => tagsCallback(JSON.parse(e.data)))
    evtSource.onerror = () => offlineCallback(true)
  }
}
