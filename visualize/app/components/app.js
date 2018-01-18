import React from 'react'
import xhr from 'tiny-xhr'
import {observable} from 'mobx'
import {NavBar, NavStore} from './navbar'
import {AddrsStore, Addrs} from './addrs'

export class AppStore {
  @observable funcs = null;

  constructor(){
    this.navStore = new NavStore(this)
    this.addrsStore = new AddrsStore(this)
  }

  async load(url){
    let response = (await xhr({
      url: url, method: 'GET', type: 'json',
    })).response
    this.funcs = response.funcs
    this.navStore.loadJson(response)
  }
}

export class App extends React.Component {
  render(){
    return pug`
      .container
        NavBar
        .bottom-container
          .funcs
          .cfg
          Addrs
    `
  }
}
