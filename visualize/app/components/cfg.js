import React from 'react'
import {inject, observer} from 'mobx-react'
import {action, observable, autorun} from 'mobx'
import * as d3 from 'd3'
import dagreD3 from 'dagre-d3'
import {highlightDeob} from '../highlight'

export class CFGStore {
  dragPt = null;
  dragCTM = null;
  // graph's top left is at (0, 0), everything else is a viewbox
  @observable vX = 0;
  @observable vY = 0;
  @observable vWidth = 0;
  @observable vHeight = 0;
  @observable mX = 0;
  @observable mY = 0;
  @observable mWidth = 0;
  @observable mHeight = 0;
}

@inject('store') @observer
export class CFG extends React.Component {
  constructor(props){
    super(props)
    autorun(this.componentDidMount.bind(this))
    window.addEventListener('resize', this.onResize.bind(this))
  }

  @action onResize(resize=true){
    const {cfgStore} = this.props.store
    const svgMain = d3.select('.cfg .main')
    const svgMinimap = d3.select('.cfg .minimap')
    const output = svgMain.select('.output')
    if(!svgMain.node()) return
    const graphBBox = svgMain.node().getBoundingClientRect()
    cfgStore.vWidth = graphBBox.width
    cfgStore.vHeight = graphBBox.height
    const outputBBox = output.node() ? output.node().getBBox() : {width: 1, height: 1}
    if(!resize){
      cfgStore.vX = (outputBBox.width - graphBBox.width) / 2
      cfgStore.vY = -30
    }
    const minimapBBox = svgMinimap.node().getBoundingClientRect()
    const scale = Math.max(outputBBox.width / minimapBBox.width, outputBBox.height / minimapBBox.height) * 1.1
    cfgStore.mX = -(scale * minimapBBox.width - outputBBox.width) / 2
    cfgStore.mY = -(scale * minimapBBox.height - outputBBox.height) / 2
    cfgStore.mWidth = scale * minimapBBox.width
    cfgStore.mHeight = scale * minimapBBox.height
  }

  renderGraph(){
    const {store} = this.props
    const funcAddr = store.selectedFunc
    const svg = d3.select('.cfg .main')

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
    svg.selectAll('.node').on('mousedown', function(){
      svg.selectAll('rect.active').remove()
      d3.event.stopPropagation()
    })
  }

  renderMinimap(){
    const svg = d3.select('.cfg .minimap')
    svg.select('.output').remove()
    const output = d3.select('.cfg .main .output')
    if(!output.node()) return
    const cloned = d3.select(output.node().cloneNode(true))
    cloned.selectAll('text').remove()
    cloned.selectAll('.path').each(function(){this.removeAttribute('marker-end')})
    cloned.selectAll('rect, .path').each(function(){this.setAttribute('vector-effect', 'non-scaling-stroke')})
    svg.select('.graph').append(() => cloned.node())
  }

  componentDidMount(){
    this.renderGraph()
    this.renderMinimap()
    this.onResize(false)
  }

  @action onDragStart(e, view=false){
    const {cfgStore} = this.props.store
    let svg = e.target
    while(svg.nodeName != 'svg') svg = svg.parentNode
    const pt = svg.createSVGPoint()
    pt.x = e.clientX
    pt.y = e.clientY
    cfgStore.dragCTM = svg.getScreenCTM().inverse()
    cfgStore.dragPt = pt.matrixTransform(cfgStore.dragCTM)
    if(view){
      cfgStore.vX = cfgStore.dragPt.x - cfgStore.vWidth / 2
      cfgStore.vY = cfgStore.dragPt.y - cfgStore.vHeight / 2
    }
    e.preventDefault()
  }

  @action onDrag(e, view=false){
    const {cfgStore} = this.props.store
    if(cfgStore.dragPt){
      const {x, y} = cfgStore.dragPt
      cfgStore.dragPt.x = e.clientX
      cfgStore.dragPt.y = e.clientY
      cfgStore.dragPt = cfgStore.dragPt.matrixTransform(cfgStore.dragCTM)
      cfgStore.vX += (view ? 1 : -1) * (cfgStore.dragPt.x - x)
      cfgStore.vY += (view ? 1 : -1) * (cfgStore.dragPt.y - y)
    }
  }

  @action onDragEnd(){
    const {cfgStore} = this.props.store
    cfgStore.dragPt = null
  }

  render(){
    const cs = this.props.store.cfgStore
    return pug`
      .cfg(ref='container')
        svg.main.graph(
          shapeRendering='crispEdges' viewBox=${`${cs.vX} ${cs.vY} ${cs.vWidth} ${cs.vHeight}`}
          onMouseDown=${this.onDragStart.bind(this)} onMouseMove=${this.onDrag.bind(this)}
          onMouseUp=${this.onDragEnd.bind(this)} onMouseOut=${this.onDragEnd.bind(this)}
        )
        svg.minimap(
          shapeRendering='crispEdges' viewBox=${`${cs.mX} ${cs.mY} ${cs.mWidth} ${cs.mHeight}`} pointerEvents='all'
          onMouseDown=${(e) => this.onDragStart(e, true)} onMouseMove=${(e) => this.onDrag(e, true)}
          onMouseUp=${this.onDragEnd.bind(this)} onMouseOut=${this.onDragEnd.bind(this)}
        )
          rect.background(x=${cs.mX} y=${cs.mY} width='100%' height='100%')
          g.graph
          rect.view(x=${cs.vX} y=${cs.vY} width=${cs.vWidth} height=${cs.vHeight} vectorEffect='non-scaling-stroke')
    `
  }
}
