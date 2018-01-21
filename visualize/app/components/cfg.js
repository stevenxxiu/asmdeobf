import React from 'react'
import {inject, observer} from 'mobx-react'
import {action, observable, autorun} from 'mobx'
import * as d3 from 'd3'
import dagreD3 from 'dagre-d3'
import {highlightDeob} from '../highlight'

export class CFGStore {
  @observable viewX = 0;
  @observable viewY = 0;
}

@inject('store') @observer
export class CFG extends React.Component {
  constructor(props){
    super(props)
    autorun(this.componentDidMount.bind(this))
    window.addEventListener('resize', this.componentDidMount.bind(this))
  }

  renderGraph(){
    const {store} = this.props
    const funcAddr = store.selectedFunc
    const svg = d3.select('.cfg .graph')

    // empty graph
    if(funcAddr == null){
      svg.select('*').remove()
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
    render(svg, g)

    // marks paths pointing back for styles
    for(let {v, w} of g.edges())
      if(g.node(v).y < g.node(w).y)
        g.edge({v, w}).elem.classList.add('back')

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
    const zoom = d3.zoom().on('zoom', () => svg.select('.output').attr('transform', d3.event.transform))
    svg.call(zoom).on('wheel.zoom', null).on('dblclick.zoom', null)
    svg.selectAll('.node').on('mousedown', function(){
      svg.selectAll('rect.active').remove()
      d3.event.stopPropagation()
    })

    // horizontally center the graph and apply vertical margin
    const contBBox = svg.node().getBoundingClientRect()
    svg.call(zoom.transform, d3.zoomIdentity.translate((contBBox.width - g.graph().width) / 2, 30))
  }

  renderMinimap(){
    const svg = d3.select('.cfg .minimap')

    // clear existing output
    svg.select('.output').remove()

    // center finder's coordinates
    const finder = svg.select('.view-finder')
    if(!finder.node()) return
    const finderBBox = finder.node().getBBox()
    finder.attr('transform', `translate(${-finderBBox.width / 2}, ${-finderBBox.height / 2})`)

    // draw mini-cfg
    const graph = d3.select('.cfg .graph .output')
    if(!graph.node()) return
    const cloned = d3.select(graph.node().cloneNode(true))
    cloned.selectAll('text').remove()
    cloned.selectAll('.path').each(function(){this.removeAttribute('marker-end')})
    cloned.selectAll('rect, .path').each(function(){this.setAttribute('vector-effect', 'non-scaling-stroke')})
    svg.insert(() => cloned.node(), '.view-loc')

    // update coordinate system so mini-cfg's matches cfg's
    const graphBBox = cloned.node().getBBox()
    const contBBox = svg.node().getBoundingClientRect()
    const scale = Math.max(graphBBox.width / contBBox.width, graphBBox.height / contBBox.height) * 1.1
    let [x, y] = /translate\(([^,]+),([^,]+)\)/.exec(cloned.attr('transform')).slice(1).map(parseFloat)
    x -= (scale * contBBox.width - graphBBox.width) / 2
    y -= (scale * contBBox.height - graphBBox.height) / 2
    const width = scale * contBBox.width
    const height = scale * contBBox.height
    svg.attr('viewBox', `${x} ${y} ${width} ${height}`)

    // update background so it fills up the svg
    d3.select('.background').attr('x', x).attr('y', y)
  }

  componentDidMount(){
    this.renderGraph()
    this.renderMinimap()
  }

  render(){
    const {cfgStore} = this.props.store
    return pug`
      .cfg(ref='container')
        svg.graph(shapeRendering='crispEdges')
        svg.minimap(shapeRendering='crispEdges')
          rect.background(width='100%', height='100%')
          g.view-loc(transform=${`translate(${cfgStore.viewX}, ${cfgStore.viewY})`})
            rect.view-finder(width='40%' height='40%' vectorEffect='non-scaling-stroke')
    `
  }
}
