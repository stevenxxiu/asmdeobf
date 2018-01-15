import React from 'react'
import {observable} from 'mobx'
import {inject, observer} from 'mobx-react'

export class AppStore {
  @observable value = 1;
}

@inject('store') @observer
export class App extends React.Component {
  render(){
    const {store} = this.props
    return pug`div ${store.value}`
  }
}
