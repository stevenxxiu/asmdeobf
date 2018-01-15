
module.exports = function(src){
  // https://github.com/sass/sass/issues/109
  return src.replace(/((?:(?:[a-z-]+)\s*,\s*)+(?:[a-z-]+))\s*:\s*(.+)/g, (_match, props, value) =>
    props.split(',').map((prop) => `${prop}: ${value}`).join(';')
  )
}
