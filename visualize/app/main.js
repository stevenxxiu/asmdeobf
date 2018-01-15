import React from 'react'
import ReactDOM from 'react-dom'
import {AppContainer} from 'react-hot-loader'
import {Provider} from 'mobx-react'
import {AppStore, App} from './components/app'

const render = (Component) => {
  const appStore = new AppStore()
  window.addEventListener('click', () => appStore.value = appStore.value + 1)
  ReactDOM.render(
    pug`
      AppContainer
        Provider(store=appStore)
          Component
    `,
    document.getElementById('root'),
  )
}

render(App)

if(module.hot){
  module.hot.accept('./components/app', () => {
    render(require('./components/app').App)
  })
}
