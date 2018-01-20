import Prism from 'prismjs'

const deobGrammar = {
  'size': {
    pattern: /(\[)\d+/,
    lookbehind: true,
  },
  'integer': /0x[\da-f]+/,
  'jmp_to': {
    pattern: /^jmp to .+/,
    inside: {
      'api': {
        pattern: /^(jmp to ).+/,
        lookbehind: true,
      },
    },
  },
  'jmp_if': /^jmp left if /,
  'var': {
    pattern: /(^|\s)\w+(_\d+)?/,
    lookbehind: true,
  },
}

export function highlightDeob(text){
  return Prism.highlight(text, deobGrammar)
    .replace(/<span /g, '<tspan ')
    .replace(/<\/span>/g, '</tspan>')
}
