import React from 'react'
import xhr from 'tiny-xhr'
import {observable} from 'mobx'
import {NavBar, NavStore} from './navbar'

export class AppStore {
  @observable selectedBlock = null;

  constructor(){
    this.navStore = new NavStore()
  }

  async load(url){
    let response = (await xhr({
      url: url, method: 'GET', type: 'json',
    })).response
    this.navStore.loadJson(response)
  }
}

export class App extends React.Component {
  render(){
    return pug`
      div
        NavBar
    `
  }
}
