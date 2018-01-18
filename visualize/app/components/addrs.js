import React from 'react'
import mergeRanges from 'merge-ranges'
import Infinite from 'react-infinite'
import {inject, observer} from 'mobx-react'
import {computed, observable} from 'mobx'
import {stringifyAddr} from '../utils'

export class AddrsStore {
  @observable windowHeight = window.innerHeight;

  constructor(rootStore){
    this.rootStore = rootStore
    window.addEventListener('resize', () => this.windowHeight = window.innerHeight)
  }

  @computed get addrs(){
    const ranges = []
    for(let addr in this.rootStore.funcs)
      for(let block of this.rootStore.funcs[addr].block)
        for(let [addr, size] of block.addr_sizes)
          ranges.push([addr, addr + size])
    const merged = mergeRanges(ranges)
    const gapped = []
    let prevEnd = null
    for(let [start, end] of merged){
      if(prevEnd !== null)
        gapped.push([true, prevEnd, start])
      gapped.push([false, start, end])
      prevEnd = end
    }
    return gapped
  }
}

@inject('store') @observer
export class Addrs extends React.Component {
  render(){
    const {addrsStore} = this.props.store
    return pug`
      .addrs.panel
        .heading Addresses
        .body
          Infinite(containerHeight=${addrsStore.rootStore.windowHeight - 82} elementHeight=22)
            ${addrsStore.addrs.map(([isGap, start, end], i) => pug`
              .text-row(class=${isGap ? 'gap': ''} key=${i}) ${stringifyAddr(start) + ' (' + stringifyAddr(end - start, 3) + ')'}
            `)}
    `
  }
}
