import React from 'react'
import Infinite from 'react-infinite'
import {inject, observer} from 'mobx-react'
import {computed, action, observable} from 'mobx'
import {stringifyAddr} from '../utils'
import {PropWidthHeight} from './propwidthheight'

export class FuncsStore {
  @observable focused = false;
  @observable filter = '';

  constructor(rootStore){
    this.rootStore = rootStore
  }

  @computed get funcs(){
    return [null, ...Object.keys(this.rootStore.funcs).map(parseInt).sort()]
  }
}

@inject('store') @observer
export class Funcs extends React.Component {
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
      .funcs.panel
        .heading Functions
        input(type='text' value=${funcsStore.filter} onChange=${(e) => funcsStore.filter = e.target.value})
        .body(tabIndex=-1 class=${funcsStore.focused ? 'active': ''} onClick=${this.onClick.bind(this)} onBlur=${this.onBlur.bind(this)})
          PropWidthHeight(propHeight='containerHeight')
            Infinite(elementHeight=22)
              ${funcsStore.funcs
                .map(addr => [addr, addr ? stringifyAddr(addr) : '-'])
                .filter(([addr, text]) => text.includes(funcsStore.filter))
                .map(([addr, text], i) =>
                  pug`.text-row(
                    key=${i} class=${addr == store.selectedFunc ? 'active': ''}
                    onClick=${() => this.props.store.selectedFunc = addr}
                  ) ${text}`
                )
              }
    `
  }
}
