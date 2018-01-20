
export function stringifyAddr(n, padLen=8){
  return n.toString(16).padStart(padLen, '0')
}
