import React from 'react'
import Infinite from 'react-infinite'
import {inject, observer} from 'mobx-react'
import {computed} from 'mobx'
import {stringifyAddr} from '../utils'

export class FuncsStore {
  constructor(rootStore){
    this.rootStore = rootStore
  }

  @computed get funcs(){
    const res = this.rootStore.funcs ? Object.keys(this.rootStore.funcs) : []
    return res.map(parseInt).sort()
  }
}

@inject('store') @observer
export class Funcs extends React.Component {
  render(){
    const {funcsStore} = this.props.store
    return pug`
      .funcs.panel
        .heading Functions
        .body
          Infinite(containerHeight=${funcsStore.rootStore.windowHeight - 82} elementHeight=22)
            ${funcsStore.funcs.map((addr, i) => pug`.text-row(key=${i}) ${stringifyAddr(addr)}`)}
    `
  }
}
