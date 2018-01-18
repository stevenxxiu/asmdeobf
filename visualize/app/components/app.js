import React from 'react'
import xhr from 'tiny-xhr'
import {observable} from 'mobx'
import {NavBar, NavStore} from './navbar'
import {FuncsStore, Funcs} from './funcs'
import {AddrsStore, Addrs} from './addrs'

export class AppStore {
  @observable funcs = null;
  @observable windowWidth = window.innerWidth;
  @observable windowHeight = window.innerHeight;

  constructor(){
    this.navStore = new NavStore(this)
    this.addrsStore = new AddrsStore(this)
    this.funcsStore = new FuncsStore(this)
    window.addEventListener('resize', () => {
      this.windowWidth = window.innerWidth
      this.windowHeight = window.innerHeight
    })
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
          Funcs
          .cfg
          Addrs
    `
  }
}
