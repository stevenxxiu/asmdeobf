import React from 'react'
import xhr from 'tiny-xhr'
import {observable, action} from 'mobx'
import {NavBar, NavStore} from './navbar'
import {FuncsStore, Funcs} from './funcs'
import {CFGStore, CFG} from './cfg'
import {AddrsStore, Addrs} from './addrs'

export class AppStore {
  @observable funcs = {};
  @observable selectedFunc = null;
  @observable start = 0;
  @observable end = 1;

  constructor(){
    this.navStore = new NavStore(this)
    this.addrsStore = new AddrsStore(this)
    this.funcsStore = new FuncsStore(this)
    this.cfgStore = new CFGStore(this)
  }

  @action async load(url){
    let response = (await xhr({
      url: url, method: 'GET', type: 'json',
    })).response
    this.funcs = response.funcs
    this.start = response.start
    this.end = response.end
    this.navStore.loadJSON(response)
  }
}

export class App extends React.Component {
  render(){
    return pug`
      .container
        NavBar
        .bottom-container
          Funcs
          CFG
          Addrs
    `
  }
}
