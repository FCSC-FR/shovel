'use strict'

/*
 * Copyright (C) 2023-2024  ANSSI
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

import Api from './api.js'

// These should match defined magics in suricata.rules
const MAGIC_EXT = {
  'GIF image': 'gif',
  'HTML document': 'html',
  'ISO Media': 'mp4',
  'JPEG image': 'jpg',
  'PDF document': 'pdf',
  'PNG image': 'png',
  'SVG Scalable Vector Graphics image': 'svg',
  'VGM Video Game Music': 'vgm',
  'RIFF (little-endian) data, WAVE audio': 'wav',
  'Web Open Font': 'woff',
  'Zip archive': 'zip'
}

const HTTP_HEADER_BL = [
  ':method',
  ':path',
  ':scheme',
  ':status',
  'accept-ranges',
  'allow',
  'cache-control',
  'connection',
  'content-length',
  'content-range',
  'content-type',
  'cross-origin-opener-policy',
  'date',
  'host',
  'last-modified',
  'location',
  'referrer-policy',
  'transfer-encoding',
  'vary',
  'x-content-type-options',
  'x-frame-options',
  undefined // header name is missing
]

/**
 * Flow display
 */
class FlowDisplay {
  constructor () {
    this.apiClient = new Api()

    // On new flow selected, update display
    window.addEventListener('locationchange', () => this.update())

    // Load config
    const appData = document.getElementById('app').dataset
    this.startTs = Math.floor(Date.parse(appData.startDate) / 1000)
    this.tickLength = Number(appData.tickLength)

    // On V key, switch view
    document.addEventListener('keyup', e => {
      if (e.target.tagName !== 'INPUT' && !e.ctrlKey && !e.shiftKey && !e.altKey && e.code === 'KeyV') {
        if (document.getElementById('display-raw-hex-tab').classList.contains('active')) {
          document.getElementById('display-raw-utf8-tab').click()
        } else {
          document.getElementById('display-raw-hex-tab').click()
        }
        e.preventDefault()
      }
    })

    // On application card tab click, update view
    document.getElementById('display-app-tabs').addEventListener('click', () => this.updateAppFileinfoViews())
  }

  /**
   * Pretty print size
   * @param {Number} size Size in bytes
   * @returns Pretty string representation
   */
  pprintSize (size) {
    if (size < 1024) {
      return `${size} B`
    }
    size = size / 1024
    if (size < 1024) {
      return `${size.toFixed(2)} kiB`
    }
    size = size / 1024
    return `${size.toFixed(2)} MiB`
  }

  /**
   * Update fileinfo cards current view in application protocol card
   */
  updateAppFileinfoViews () {
    const appViewType = document.getElementById('display-app-tabs').querySelector('.active')?.id.slice(12, -4)
    document.querySelectorAll('.display-app-render').forEach(e => e.classList.toggle('active', appViewType === 'render'))
    document.querySelectorAll('.display-app-utf8').forEach(e => e.classList.toggle('active', appViewType === 'utf8'))
    document.querySelectorAll('.display-app-hex').forEach(e => e.classList.toggle('active', appViewType === 'hex'))
  }

  /**
   * Get extension from libmagic output
   * @param {String} magic - Value returned by libmagic
   * @returns Extension corresponding to this magic
   */
  getExtFromMagic (magic) {
    for (const [magicPrefix, ext] of Object.entries(MAGIC_EXT)) {
      if (magic.startsWith(magicPrefix)) {
        return ext
      }
    }
    return 'txt'
  }

  /**
   * Highlight payload using provided keywords and current search param
   *
   * Escape HTML and highlighted keywords to prevent XSS
   * @param {String} content
   * @param {Array} keywords - Keywords to highlight
   * @returns HTML representation
   */
  highlightPayload = (content, keywords) => {
    const htmlEscape = (str) => str.replace(/[\u00A0-\u9999<>&]/g, i => '&#' + i.charCodeAt(0) + ';')
    content = htmlEscape(content)
    keywords?.forEach(k => {
      k = htmlEscape(k)
      content = content.replaceAll(k, `<mark>${k}</mark>`)
    })
    const url = new URL(document.location)
    let search = url.searchParams.get('search')
    if (search) {
      search = htmlEscape(search)
      content = content.replaceAll(search, `<mark>${search}</mark>`)
    }
    return content
  }

  /**
   * Render blob using file type
   *
   * @param {Blob} blob - Data to represent
   * @param {String} fileType - File type (e.g. pdf, doc, svg)
   * @param {HTMLElement} targetEl - Renderer will be appened as child of this element
   */
  renderBlob (blob, fileType, targetEl) {
    if (['gif', 'jpg', 'png', 'svg'].includes(fileType)) {
      const imgEl = document.createElement('img')
      imgEl.classList.add('img-payload')
      imgEl.src = URL.createObjectURL(blob)
      targetEl.appendChild(imgEl)
    } else if (fileType === 'mp4') {
      const videoEl = document.createElement('video')
      videoEl.classList.add('img-payload')
      videoEl.controls = true
      videoEl.src = URL.createObjectURL(blob)
      targetEl.appendChild(videoEl)
    } else if (fileType === 'wav') {
      const audioEl = document.createElement('audio')
      audioEl.classList.add('audio-payload')
      audioEl.controls = true
      audioEl.src = URL.createObjectURL(blob)
      targetEl.appendChild(audioEl)
    } else if (fileType === 'pdf') {
      const iframeEl = document.createElement('iframe')
      iframeEl.width = 500
      iframeEl.height = 700
      blob = blob.slice(0, blob.size, 'application/pdf')
      iframeEl.src = URL.createObjectURL(blob)
      targetEl.appendChild(iframeEl)
    } else if (fileType === 'html') {
      const iframeEl = document.createElement('iframe')
      iframeEl.classList.add('w-100', 'bg-white')
      iframeEl.height = 300
      iframeEl.sandbox = ''
      blob = blob.slice(0, blob.size, 'text/html')
      iframeEl.src = URL.createObjectURL(blob)
      targetEl.appendChild(iframeEl)
    }
  }

  /**
   * Render a `hexdump -C` like output
   * @param {Uint8Array} byteArray
   * @returns String representation
   */
  renderHexDump (byteArray) {
    let hexdump = ''

    const asciiRepr = slice => {
      let ascii = ''
      slice.forEach((b) => {
        if (b >= 0x20 && b < 0x7F) {
          ascii += String.fromCharCode(b)
        } else {
          ascii += '.'
        }
      })
      return ascii
    }

    byteArray.forEach((b, i) => {
      if (i % 16 === 0) {
        hexdump += i.toString(16).padStart(8, '0') + '  '
      }

      hexdump += b.toString(16).padStart(2, '0') + ' '

      if (i % 16 === 15 || i === byteArray.length - 1) {
        if (i % 16 !== 15) {
          hexdump += ' '.repeat((15 - (i % 16)) * 3)
          if (i % 16 < 8) {
            hexdump += ' '
          }
        }
        const sliceStart = Math.floor(i / 16) * 16
        const slice = byteArray.slice(sliceStart, sliceStart + 16)
        hexdump += ` |${asciiRepr(slice)}|\n`
      } else if (i % 8 === 7) {
        hexdump += ' '
      }
    })

    return hexdump
  }

  async update () {
    // Show welcome page when flow is not found or not selected
    const url = new URL(document.location)
    const flowId = url.searchParams.get('flow')
    const flow = flowId ? await this.apiClient.getFlow(flowId) : null
    document.getElementById('display-welcome').classList.toggle('d-none', flow !== null)
    document.getElementById('display-flow').classList.toggle('d-none', flow === null)
    document.getElementById('display-alerts').classList.toggle('d-none', flow === null)
    document.getElementById('display-down').classList.add('d-none')
    document.getElementById('display-app').classList.add('d-none')
    document.getElementById('display-raw').classList.add('d-none')
    if (flow === null) {
      document.title = 'Shovel'
      return
    }

    // Format flow data
    const dateParams = {
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
      fractionalSecondDigits: 3
    }
    const dateStart = new Date(flow.flow.ts_start / 1000)
    const formatedDateStart = new Intl.DateTimeFormat(undefined, dateParams).format(dateStart)
    const dateEnd = new Date(flow.flow.ts_end / 1000)
    const formatedDateEnd = new Intl.DateTimeFormat(undefined, dateParams).format(dateEnd)
    const srcIpPort = flow.flow.src_ip + (flow.flow.src_port ? `:${flow.flow.src_port}` : '')
    const destIpPort = flow.flow.dest_ip + (flow.flow.dest_port ? `:${flow.flow.dest_port}` : '')

    // Change document title
    document.title = `${destIpPort} - Shovel`

    // Flow card
    document.getElementById('display-flow-time').textContent = `From ${formatedDateStart}\n  to ${formatedDateEnd}`
    document.getElementById('display-flow-time').title = `${flow.flow.ts_start} - ${flow.flow.ts_end}`
    document.getElementById('display-flow-pkt').textContent = `${flow.flow.proto} flow from ${srcIpPort} to ${destIpPort}\n──► ${flow.flow.pkts_toserver} packets (${this.pprintSize(flow.flow.bytes_toserver)})\n◀── ${flow.flow.pkts_toclient} packets (${this.pprintSize(flow.flow.bytes_toclient)})`
    document.getElementById('display-flow-pcap').href = `/api/flow/${flowId}/pcap`
    if (this.tickLength > 0) {
      document.getElementById('display-flow-tick').classList.remove('d-none')
      const tick = ((flow.flow.ts_start / 1000000 - this.startTs) / this.tickLength).toFixed(3)
      document.querySelector('#display-flow-tick > a > span').textContent = tick
      document.querySelector('#display-flow-tick > a').dataset.ts = flow.flow.ts_start
    }

    // Alert and anomaly cards
    const alertsDiv = document.getElementById('display-alerts')
    while (alertsDiv.lastChild) {
      alertsDiv.removeChild(alertsDiv.lastChild)
    }
    flow.alert?.forEach(data => {
      if (data.signature) {
        const cardEl = document.createElement('div')
        cardEl.classList.add('card', 'm-3', 'bg-body', 'font-monospace', `border-${data.color}`)
        const cardHeader = document.createElement('div')
        cardHeader.classList.add('card-header')
        cardHeader.textContent = data.signature
        cardHeader.title = `Suricata alert rule with sid ${data.signature_id}.`
        cardEl.appendChild(cardHeader)
        alertsDiv.appendChild(cardEl)
      }
    })
    flow.anomaly?.forEach(data => {
      const cardEl = document.createElement('div')
      cardEl.classList.add('card', 'm-3', 'bg-body', 'font-monospace', 'border-warning')
      const cardHeader = document.createElement('div')
      cardHeader.classList.add('card-header')
      cardHeader.textContent = `Dissection anomaly: ${JSON.stringify(data)}`
      cardEl.appendChild(cardHeader)
      alertsDiv.appendChild(cardEl)
    })

    // Application protocol card
    const appProto = flow.flow.app_proto?.replace('http2', 'http')
    const flowEstablished = flow.flow.state !== 'new'
    document.getElementById('display-down').classList.toggle('d-none', flowEstablished)
    if (appProto && appProto !== 'failed' && flow[appProto] !== undefined) {
      document.getElementById('display-app').classList.remove('d-none')
      document.querySelector('#display-app > header > a').classList.toggle('d-none', appProto !== 'http')
      document.querySelector('#display-app > header > h1 > a > span').textContent = appProto.toUpperCase()
      const body = document.querySelector('#display-app > div > pre')
      body.textContent = ''

      // In the case of HTTP, add some metadata at the top of the card
      if (appProto === 'http' || appProto === 'http2') {
        document.querySelector('#display-app > header > a').href = `api/replay-http/${flowId}`
        const allRequestHeaders = new Set()
        const allResponseHeaders = new Set()
        flow[appProto].forEach(data => {
          data.request_headers?.filter(x => !HTTP_HEADER_BL.includes(x?.name?.toLowerCase()))?.forEach(x => allRequestHeaders.add(`${x.name}: ${x.value}`))
          data.response_headers?.filter(x => !HTTP_HEADER_BL.includes(x?.name?.toLowerCase()))?.forEach(x => allResponseHeaders.add(`${x.name}: ${x.value}`))
        })
        body.textContent += [...allRequestHeaders].join('\n') + '\n'
        body.textContent += [...allResponseHeaders].join('\n') + '\n\n'
      }

      flow[appProto].forEach((data, txId) => {
        const spanEl = document.createElement('span')
        if (appProto === 'http' || appProto === 'http2') {
          // Format HTTP dissection
          spanEl.classList.add('fw-bold')
          spanEl.textContent = `${data.http_method ?? '?'} http://${data.hostname}:${data.http_port ?? flow.flow.dest_port}${data.url ?? ''} ${data.protocol ?? ''}  ◄ ${data.status ?? '?'}\n`
        } else {
          // Directly pretty-print JSON Suricata app protocol dissection
          spanEl.textContent += `${JSON.stringify(data, null, 4)}\n`
        }
        body.appendChild(spanEl)

        // Add corresponding fileinfo
        flow.fileinfo?.filter(d => d.tx_id === txId).forEach((data, i) => {
          const fileHref = `api/filedata/${data.sha256}`
          const ext = this.getExtFromMagic(data.magic ?? '')

          // Create "Download file" button
          const downloadBtn = document.createElement('a')
          downloadBtn.classList.add('text-nowrap')
          downloadBtn.href = fileHref
          downloadBtn.download = `${data.filename?.replace(/[^A-Za-z0-9]/g, '_')}.${ext}`
          downloadBtn.textContent = 'Download file'

          // Create views
          const renderView = document.createElement('div')
          const utf8View = document.createElement('code')
          const hexView = document.createElement('code')
          utf8View.innerText = ' ' // prevent single-line flicker on page load
          hexView.innerText = ' '
          fetch(fileHref).then(r => r.blob()).then(blob => {
            this.renderBlob(blob, ext, renderView)
            blob.text().then(t => {
              utf8View.innerHTML = this.highlightPayload(t, flow.flow.flowvars?.map(d => d.match))
              if (!renderView.firstChild) {
                // no render done, show UTF-8 on render view
                const renderCodeEl = document.createElement('code')
                renderCodeEl.innerHTML = this.highlightPayload(t, flow.flow.flowvars?.map(d => d.match))
                renderView.appendChild(renderCodeEl)
              }
            })
            blob.arrayBuffer().then(arrayBuf => {
              const b = new Uint8Array(arrayBuf)
              hexView.textContent = this.renderHexDump(b)
            })
          })

          // Clone fileinfo template and fill with content
          const cardEl = document.getElementById('display-app-fileinfo').content.cloneNode(true)
          cardEl.querySelector('header > a').href = `#fileinfo-${txId}-${i}`
          cardEl.querySelector('header > a > span').textContent = `File ${data.filename}` + (data.magic ? `, ${data.magic}` : '')
          cardEl.querySelector('header').appendChild(downloadBtn)
          cardEl.querySelector('div.collapse').id = `fileinfo-${txId}-${i}`
          cardEl.querySelector('pre.display-app-render').appendChild(renderView)
          cardEl.querySelector('pre.display-app-utf8').appendChild(utf8View)
          cardEl.querySelector('pre.display-app-hex').appendChild(hexView)
          body.appendChild(cardEl)
          this.updateAppFileinfoViews()
        })

        // Add extra HTTP redirection information if defined
        if (appProto === 'http' || appProto === 'http2') {
          const locationHeader = data.response_headers?.find(x => x?.name?.toLowerCase() === 'location')
          if (locationHeader) {
            const spanEl = document.createElement('p')
            spanEl.classList.add('mt-1', 'mb-2', 'ms-3')
            spanEl.textContent += `Redirection to ${locationHeader.value}`
            body.appendChild(spanEl)
          }
        }
      })
    }

    // Show raw data card if a TCP or UDP connection was established
    if (['TCP', 'UDP'].includes(flow.flow.proto) && flowEstablished) {
      document.getElementById('display-raw').classList.remove('d-none')
      document.getElementById('display-raw-replay').href = `api/replay-raw/${flowId}`

      // Display loading indicator before sending HTTP request
      const utf8View = document.getElementById('display-raw-utf8')
      const hexView = document.getElementById('display-raw-hex')
      utf8View.textContent = 'Loading...'
      hexView.textContent = 'Loading...'

      const chunks = await this.apiClient.getFlowRaw(flowId)
      utf8View.textContent = ''
      hexView.textContent = ''
      chunks.forEach(chunk => {
        const byteArray = Uint8Array.from(atob(chunk.data), c => c.charCodeAt(0))
        const utf8Decoder = new TextDecoder()

        const codeElUtf8 = document.createElement('code')
        codeElUtf8.classList.add('text-white')
        codeElUtf8.classList.toggle('bg-danger', chunk.server_to_client === 0)
        codeElUtf8.classList.toggle('bg-success', chunk.server_to_client === 1)
        codeElUtf8.innerHTML = this.highlightPayload(utf8Decoder.decode(byteArray), flow.flow.flowvars?.map(d => d.match))
        utf8View.appendChild(codeElUtf8)

        const codeElHex = document.createElement('code')
        codeElHex.classList.add('text-white')
        codeElHex.classList.toggle('bg-danger', chunk.server_to_client === 0)
        codeElHex.classList.toggle('bg-success', chunk.server_to_client === 1)
        codeElHex.textContent = this.renderHexDump(byteArray) + '\n'
        hexView.appendChild(codeElHex)
      })
    }
  }
}

const flowDisplay = new FlowDisplay()
flowDisplay.update()
