import React from 'react'
import mergeRanges from 'merge-ranges'
import {inject, observer} from 'mobx-react'
import {computed, observable, autorun, action} from 'mobx'

export class NavStore {
  @observable start = 0;
  @observable end = 1;
  @observable curStart = 0;
  @observable curEnd = 1;
  @observable windowWidth = 0;

  constructor(rootStore){
    this.rootStore = rootStore
    this.windowWidth = window.innerWidth
    window.addEventListener('resize', () => this.windowWidth = window.innerWidth)
  }

  @computed get ranges(){
    const ranges = []
    const step = (this.curEnd - this.curStart) / (this.windowWidth * 2)
    for(let addr in this.rootStore.funcs)
      for(let block of this.rootStore.funcs[addr].block)
        for(let [addr, size] of block.addr_sizes){
          const start = addr
          const end = addr + size - 1
          if(self.curStart <= start && end <= self.curEnd)
            ranges.push([addr - step, addr + size - 1 + step])
        }
    return mergeRanges(ranges)
  }

  @action loadJson(obj){
    this.curStart = this.start = obj.start
    this.curEnd = this.end = obj.end
  }
}

@inject('store') @observer
class NavContent extends React.Component {
  constructor(props){
    super(props)
    autorun(this.renderCanvas.bind(this))
  }

  renderCanvas(){

  }

  render(){
    const {navStore} = this.props.store
    return pug`canvas(ref='canvas' width=${navStore.windowWidth - 50} height=30)`
  }
}

@inject('store') @observer
export class NavBar extends React.Component {
  render(){
    // XXX include a tooltip when hovering to show location
    // XXX include zoom (with panning left right, and indicators on left/right)
    const {navStore} = this.props.store
    return pug`
      .nav-bar
        .nav-ind
          i.fa.fa-chevron-left(class=${navStore.curStart == navStore.start ? 'inactive' : ''})
        .nav-content
          NavContent
        .nav-ind
          i.fa.fa-chevron-right(class=${navStore.curEnd == navStore.end ? 'inactive' : ''})
    `
  }
}
