import React from 'react'
import {inject, observer} from 'mobx-react'
import {autorun} from 'mobx'
import * as d3 from 'd3'
import dagreD3 from 'dagre-d3'
import {PropWidthHeight} from './propwidthheight'
import {highlightDeob} from '../highlight'

@inject('store') @observer
export class CFG extends React.Component {
  constructor(props){
    super(props)
    autorun(this.componentDidMount.bind(this))
  }

  componentDidMount(){
    const {store} = this.props
    const funcAddr = store.selectedFunc
    const svg = d3.select('.cfg svg')
    const inner = svg.select('g')

    // empty graph
    if(funcAddr == null){
      inner.select('*').remove()
      return
    }

    // setup graph data
    const g = new dagreD3.graphlib.Graph().setGraph({}).setDefaultEdgeLabel(() => ({}))
    const blocks = store.funcs[funcAddr].block
    for(let [id, block] of Object.entries(blocks)){
      const group = document.createElementNS('http://www.w3.org/2000/svg', 'g')
      for(let [i, line] of block.text.split('\n').entries())
        d3.select(group).append('text').append('tspan').attr('dy', `${i + 1}em`).html(highlightDeob(line))
      g.setNode(id, {label: group, labelType: 'svg'})
    }
    for(let id of g.nodes()){
      const node = g.node(id)
      node.paddingTop = 0
      node.paddingLeft = node.paddingRight = node.paddingBottom = 5
    }
    for(let [id, block] of Object.entries(blocks)){
      for(let [i, child] of block.children.entries()){
        const props = {}
        if(block.text.includes('jmp left if'))
          props['class'] = i == 0 ? 'left' : 'right'
        g.setEdge(id, child, props)
      }
    }

    // render
    const render = new dagreD3.render()
    render(inner, g)

    // marks paths pointing back for styles
    svg.selectAll('.edgePath .path').each(function({v, w}){
      if(g.node(v).y > g.node(w).y)
        this.parentNode.classList.add('back')
    })

    // clicking variables highlights them
    svg.selectAll('.var').on('mousedown', function(){
      const node = this
      let parent = node
      while(parent.nodeName != 'g') parent = parent.parentNode
      svg.selectAll('rect.active').remove()
      d3.select(parent).selectAll('.var').each(function(){
        if(this.textContent == node.textContent){
          const extent = this.getExtentOfChar(0) // pos + dimensions of the first glyph
          const width = this.getComputedTextLength() // width of the tspan
          d3.select(parent).insert('rect', ':first-child').classed('active', true)
            .attr('x', extent.x).attr('y', extent.y).attr('width', width).attr('height', extent.height)
        }
      })
      d3.event.stopPropagation()
    })

    // set up panning
    const zoom = d3.zoom().on('zoom', () => inner.attr('transform', d3.event.transform))
    svg.call(zoom).on('wheel.zoom', null).on('dblclick.zoom', null)
    svg.selectAll('.node').on('mousedown', function(){
      svg.selectAll('rect.active').remove()
      d3.event.stopPropagation()
    })

    // horizontally center the graph and apply vertical margin
    svg.call(zoom.transform, d3.zoomIdentity.translate((svg.attr('width') - g.graph().width) / 2, 30))
  }

  render(){
    return pug`
      .cfg(ref='container')
        PropWidthHeight(propWidth='width' propHeight='height')
          svg(shapeRendering='crispEdges')
            g
    `
  }
}
