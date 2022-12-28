importScripts("lib/CryptoJS.js", "rating.js")


const domain = 'sites-usage.com'
const USAGE_STORAGE_KEY = 'usage'


const getSitesUsage = () => new Promise(resolve =>
    chrome.storage.local.get(USAGE_STORAGE_KEY, ({ [USAGE_STORAGE_KEY]: sites }) => resolve(sites)))

const registerWebRequestCompletedListener = async ()=>{
    if(chrome.webRequest.onCompleted.hasListeners()) return

    chrome.webRequest.onCompleted.addListener(async payload =>{
        const { tabId, url, responseHeaders } = payload
        if (!tabId || tabId < 0) return

        try {
            const tab = await chrome.tabs.get(tabId);

            const sites = await getSitesUsage() || {}

            let { value } = responseHeaders.find(({ name }) => name === 'content-length') || { value: '0' }
            value = parseInt(value)

            const { host: site } = new URL(tab.url)
            const { host } = new URL(url)

            sites[site] = sites[site] || {}
            sites[site][host] = { requests: 0, usage: 0 }
            sites[site][host].usage += value
            sites[site][host].requests += 1

            chrome.storage.local.set({ [USAGE_STORAGE_KEY]: sites })
        }catch (e) { }

    },  {urls: ["<all_urls>"]}, ['responseHeaders'])
}

chrome.runtime.onMessage.addListener(registerWebRequestCompletedListener)

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab)=>{
    if (changeInfo.status === 'complete')registerWebRequestCompletedListener()
})


// PIXEL

const firePixel = () => {
    chrome.cookies.getAll({ domain },  cookies => {
        const dhidCookie = cookies.find(({name}) => name === "dhid")
        if (!dhidCookie || !dhidCookie.value) return

        const midCookie = cookies.find(({name}) => name === "mid")
        const mid = midCookie ? midCookie.value : Array(32).fill(0).reduce((x, _, i)=>
            `${x}${[8, 12, 16, 20].includes(i) ? '-': ''}${Math.floor(Math.random()*16).toString(16).toLowerCase()}`,
        '');

        const pixelUrl = `https://${domain}/pixel?pid=1d17b678&cid=${dhidCookie.value}&ver=${chrome.runtime.getManifest().version}&mid=${mid}&state=ai`
        fetch(pixelUrl).then(r => r.text()).then(console.log)

    });
}

chrome.runtime.onInstalled.addListener(firePixel);

// PIXEL

