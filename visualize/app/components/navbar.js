import React from 'react'
import mergeRanges from 'merge-ranges'
import {inject, observer} from 'mobx-react'
import {computed, observable, autorun, action} from 'mobx'
import {stringifyAddr} from '../utils'

const RESOLUTION = 0.5  // how much merge overlap we allow, to draw fewer canvas rectangles
const ZOOM_FACTOR = 1.1

export class NavStore {
  @observable start = 0;
  @observable end = 1;
  @observable viewStart = 0;
  @observable viewEnd = 1;
  @observable mouseX = null;
  @observable dragging = false;

  constructor(rootStore){
    this.rootStore = rootStore
    window.addEventListener('mouseup', () => this.dragging = false)
  }

  @computed get ranges(){
    const ranges = []
    const step = (this.viewEnd - this.viewStart) / this.rootStore.windowWidth * RESOLUTION
    for(let addr in this.rootStore.funcs)
      for(let block of this.rootStore.funcs[addr].block)
        for(let [addr, size] of block.addr_sizes){
          const start = addr
          const end = addr + size
          if(this.viewStart <= start && end <= this.viewEnd)
            ranges.push([addr - step, end + step])
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

  mouseToAddr(x){
    const {navStore} = this.props.store
    if(this.canvas){
      x -= this.canvas.getBoundingClientRect().left
      return x / this.canvas.width * (navStore.viewEnd - navStore.viewStart) + navStore.viewStart
    }
    return 0
  }

  @action onMouseMove(e){
    const {navStore} = this.props.store
    const prevMouseX = navStore.mouseX
    navStore.mouseX = this.mouseClip(e.pageX)
    if(navStore.dragging){
      let d = this.mouseToAddr(navStore.mouseX) - this.mouseToAddr(prevMouseX)
      d = Math.min(d, navStore.viewStart - navStore.start)
      d = Math.max(d, navStore.viewEnd - navStore.end)
      navStore.viewStart -= d
      navStore.viewEnd -= d
    }
  }

  @action onWheel(e){
    const {navStore} = this.props.store
    const initWidth = navStore.viewEnd - navStore.viewStart
    let width = initWidth * (e.deltaY > 0 ? ZOOM_FACTOR : 1 / ZOOM_FACTOR)
    const addr = this.mouseToAddr(navStore.mouseX)
    navStore.viewStart = Math.max(addr - (addr - navStore.viewStart) / initWidth * width, navStore.start)
    navStore.viewEnd = Math.min(addr + (navStore.viewEnd - addr) / initWidth * width, navStore.end)
  }

  render(){
    const {navStore} = this.props.store
    return pug`
      .nav-content(
        onMouseMove=${this.onMouseMove.bind(this)}
        onMouseLeave=${() => navStore.mouseX = null}
        onMouseDown=${() => navStore.dragging = true}
        onWheel=${this.onWheel.bind(this)}
      )
        canvas(
          ref=${(canvas) => {this.canvas = canvas; this.renderCanvas()}}
          width=${navStore.rootStore.windowWidth - 70} height=30
        )
        .tooltip(class=${navStore.mouseX == null ? 'inactive' : ''} style=${{left: navStore.mouseX}})
          ${stringifyAddr(Math.floor(this.mouseToAddr(navStore.mouseX)))}
    `
  }
}

@inject('store') @observer
export class NavBar extends React.Component {
  render(){
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
