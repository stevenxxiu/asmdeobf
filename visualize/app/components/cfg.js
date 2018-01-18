import React from 'react'
import {inject, observer} from 'mobx-react'
import {autorun} from 'mobx'
import * as d3 from 'd3'
import dagreD3 from 'dagre-d3'

@inject('store') @observer
export class CFG extends React.Component {
  constructor(props){
    super(props)
    this.container = null
    autorun(this.renderGraph.bind(this))
  }

  renderGraph(){
    const func = this.props.store.selectedFunc
    if(this.container && func !== null){
      const g = new dagreD3.graphlib.Graph().setGraph({})
      // Object.keys(func).forEach(addr => g.setNode(addr, {label: addr}))

      var states = [
        'CLOSED', 'LISTEN', 'SYN RCVD', 'SYN SENT',
        'ESTAB', 'FINWAIT-1', 'CLOSE WAIT', 'FINWAIT-2',
        'CLOSING', 'LAST-ACK', 'TIME WAIT',
      ]

      states.forEach((state) => g.setNode(state, { label: state }))

      g.setEdge('CLOSED',     'LISTEN',     { label: 'open' })
      g.setEdge('LISTEN',     'SYN RCVD',   { label: 'rcv SYN' })
      g.setEdge('LISTEN',     'SYN SENT',   { label: 'send' })
      g.setEdge('LISTEN',     'CLOSED',     { label: 'close' })
      g.setEdge('SYN RCVD',   'FINWAIT-1',  { label: 'close' })
      g.setEdge('SYN RCVD',   'ESTAB',      { label: 'rcv ACK of SYN' })
      g.setEdge('SYN SENT',   'SYN RCVD',   { label: 'rcv SYN' })
      g.setEdge('SYN SENT',   'ESTAB',      { label: 'rcv SYN, ACK' })
      g.setEdge('SYN SENT',   'CLOSED',     { label: 'close' })
      g.setEdge('ESTAB',      'FINWAIT-1',  { label: 'close' })
      g.setEdge('ESTAB',      'CLOSE WAIT', { label: 'rcv FIN' })
      g.setEdge('FINWAIT-1',  'FINWAIT-2',  { label: 'rcv ACK of FIN' })
      g.setEdge('FINWAIT-1',  'CLOSING',    { label: 'rcv FIN' })
      g.setEdge('CLOSE WAIT', 'LAST-ACK',   { label: 'close' })
      g.setEdge('FINWAIT-2',  'TIME WAIT',  { label: 'rcv FIN' })
      g.setEdge('CLOSING',    'TIME WAIT',  { label: 'rcv ACK of FIN' })
      g.setEdge('LAST-ACK',   'CLOSED',     { label: 'rcv ACK of FIN' })
      g.setEdge('TIME WAIT',  'CLOSED',     { label: 'timeout=2MSL' })

      g.nodes().forEach(function(v) {
        var node = g.node(v)
        node.rx = node.ry = 5
      })

      g.node('CLOSED').style = 'fill: #f77'
      g.node('ESTAB').style = 'fill: #7f7'

      const svg = d3.select('.cfg svg')
      const inner = svg.select('.cfg g')
      svg.attr('width', this.container.offsetWidth - 2)
      svg.attr('height', this.container.offsetHeight - 2)

      // render
      const render = new dagreD3.render()
      render(inner, g)

      // set up panning
      const zoom = d3.zoom().on('zoom', () => inner.attr('transform', d3.event.transform))
      svg.call(zoom).on('wheel.zoom', null).on('dblclick.zoom', null)

      // horizontally center the graph and apply vertical margin
      svg.call(zoom.transform, d3.zoomIdentity.translate((svg.attr('width') - g.graph().width) / 2, 20))
    }
  }

  render(){
    return pug`
      .cfg(ref=${(e) => {this.container = e; this.renderGraph()}})
        svg
          g
    `
  }
}
