import React from 'react'
import {action, observable} from 'mobx'
import {observer} from 'mobx-react'

@observer
export class PropWidthHeight extends React.Component {
  @observable width = 1;
  @observable height = 1;

  constructor(props){
    super(props)
    this.container = null
    window.addEventListener('resize', this.update.bind(this))

  }

  @action update(){
    if(this.container){
      this.width = this.container.offsetWidth
      this.height = this.container.offsetHeight
    }
  }

  render(){
    /* eslint-disable indent */
    return pug`
      div(ref=${(container) => {this.container = container; this.update()}} style={width: '100%', height: '100%'})
        ${React.Children.map(this.props.children, child =>
          React.cloneElement(child, {[this.props.propWidth]: this.width, [this.props.propHeight]: this.height})
        )}
    `
  }
}
