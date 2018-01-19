import React from 'react'
import Infinite from 'react-infinite'
import {inject, observer} from 'mobx-react'
import {computed, action, observable} from 'mobx'
import {stringifyAddr} from '../utils'

export class FuncsStore {
  @observable containerHeight = 1;
  @observable focused = false;

  constructor(rootStore){
    this.rootStore = rootStore
  }

  @computed get funcs(){
    const res = [null]
    res.push(...Object.keys(this.rootStore.funcs).map(parseInt).sort())
    return res
  }
}

@inject('store') @observer
export class Funcs extends React.Component {
  constructor(props){
    super(props)
    this.body = null
    window.addEventListener('resize', this.updateHeight.bind(this))
  }

  @action updateHeight(){
    const {funcsStore} = this.props.store
    if(this.body)
      funcsStore.containerHeight = this.body.offsetHeight
  }

  @action selectFunc(addr){
    this.props.store.selectedFunc = addr
  }

  @action onClick(){
    this.props.store.funcsStore.focused = true
  }

  @action onBlur(){
    this.props.store.funcsStore.focused = false
  }

  render(){
    const {store} = this.props
    const {funcsStore} = store
    return pug`
      .funcs.panel(tabIndex=-1 class=${funcsStore.focused ? 'active': ''} onClick=${this.onClick.bind(this)} onBlur=${this.onBlur.bind(this)})
        .heading Functions
        .body(ref=${(body) => {this.body = body; this.updateHeight()}})
          Infinite(containerHeight=${funcsStore.containerHeight} elementHeight=22)
            ${funcsStore.funcs.map((addr, i) =>
              pug`.text-row(
                key=${i} class=${addr == store.selectedFunc ? 'active': ''} onClick=${() => this.selectFunc(addr)}
              ) ${addr ? stringifyAddr(addr) : '-'}`
            )}
    `
  }
}
