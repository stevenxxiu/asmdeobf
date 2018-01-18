import React from 'react'
import mergeRanges from 'merge-ranges'
import {inject, observer} from 'mobx-react'
import {computed, observable, autorun, action} from 'mobx'

const RESOLUTION = 0.5  // how much merge overlap we allow, to optimize canvas operations

export class NavStore {
  @observable start = 0;
  @observable end = 1;
  @observable viewStart = 0;
  @observable viewEnd = 1;
  @observable windowWidth = 0;
  @observable mouseX = null;

  constructor(rootStore){
    this.rootStore = rootStore
    this.windowWidth = window.innerWidth
    window.addEventListener('resize', () => this.windowWidth = window.innerWidth)
  }

  @computed get ranges(){
    const ranges = []
    const step = (this.viewEnd - this.viewStart) / this.windowWidth * RESOLUTION
    for(let addr in this.rootStore.funcs)
      for(let block of this.rootStore.funcs[addr].block)
        for(let [addr, size] of block.addr_sizes){
          const start = addr
          const end = addr + size - 1
          if(this.viewStart <= start && end <= this.viewEnd)
            ranges.push([addr - step, addr + size - 1 + step])
        }
    return mergeRanges(ranges)
  }

  @action loadJson(obj){
    this.viewStart = this.start = obj.start
    this.viewEnd = this.end = obj.end
  }
}

@inject('store') @observer
class NavContent extends React.Component {
  constructor(props){
    super(props)
    this.canvas = null
    autorun(this.renderCanvas.bind(this))
  }

  renderCanvas(){
    const {navStore} = this.props.store
    const ranges = navStore.ranges
    if(this.canvas){
      const ctx = this.canvas.getContext('2d')
      ctx.fillStyle = '#bbb'
      ctx.fillRect(0, 0, this.canvas.width, this.canvas.height)
      ctx.fillStyle = '#00e'
      const viewTrans = navStore.viewStart
      const viewScale = this.canvas.width / (navStore.viewEnd - navStore.viewStart)
      for(let [curStart, curEnd] of ranges)
        ctx.fillRect((curStart - viewTrans) * viewScale, 0, (curEnd - curStart) * viewScale, this.canvas.height)
    }
  }

  mouseClip(x){
    if(this.canvas){
      const rect = this.canvas.getBoundingClientRect()
      return Math.min(Math.max(x, rect.left), rect.right)
    }
    return 0
  }

  mouseToAddress(x){
    const {navStore} = this.props.store
    if(this.canvas){
      x -= this.canvas.getBoundingClientRect().left
      return Math.round(x / this.canvas.width * (navStore.viewEnd - navStore.viewStart) + navStore.viewStart)
    }
    return 0
  }

  render(){
    const {navStore} = this.props.store
    return pug`
      .nav-content(
        onMouseMove=${(e) => navStore.mouseX = this.mouseClip(e.screenX)}
        onMouseLeave=${() => navStore.mouseX = null}
      )
        canvas(
          ref=${(canvas) => {this.canvas = canvas; this.renderCanvas()}}
          width=${navStore.windowWidth - 70} height=30
        )
        .tooltip(class=${navStore.mouseX == null ? 'inactive' : ''} style=${{left: navStore.mouseX}})
          ${this.mouseToAddress(navStore.mouseX).toString(16).padStart(8, '0').toUpperCase()}
    `
  }
}

@inject('store') @observer
export class NavBar extends React.Component {
  render(){
    // XXX include zoom (with panning left right, and indicators on left/right)
    const {navStore} = this.props.store
    return pug`
      .nav-bar
        .nav-ind
          i.fa.fa-chevron-left(class=${navStore.viewStart == navStore.start ? 'inactive' : ''})
        NavContent
        .nav-ind
          i.fa.fa-chevron-right(class=${navStore.viewEnd == navStore.end ? 'inactive' : ''})
    `
  }
}
