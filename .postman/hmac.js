const moment = require('moment')
const url = require('url')
const time = moment().utc()
const EOL = "\n"
const pathname = url.parse(request.url).pathname
const domain = url.parse(request.url).hostname
const port = url.parse(request.url).port || 443
const ts = time.unix()
const nonce = pm.variables.replaceIn('{{$randomPassword}}')
const id = pm.environment.get("LOCAL_API_KEY")
const secret = pm.environment.get("LOCAL_API_SECRET_KEY")
let canonical_string = ts + EOL + nonce + EOL + request.method.toUpperCase() + EOL + pathname + EOL + domain + EOL + port
if(pm.request.body.raw){
    canonical_string += EOL + btoa(pm.request.body.raw)
}
console.log(canonical_string)
const hash = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA512, secret)
hash.update(canonical_string)
const mac = hash.finalize()
const header = `HMAC id="${id}", nonce="${nonce}", mac="${mac}", ts="${ts}"`
pm.request.headers.add({key: "Authorization", value: header})
