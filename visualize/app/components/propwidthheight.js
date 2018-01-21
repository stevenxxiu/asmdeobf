import React from 'react'
import {action, observable} from 'mobx'
import {observer} from 'mobx-react'

@observer
export class PropWidthHeight extends React.Component {
  @observable width = 1;
  @observable height = 1;

  constructor(props){
    super(props)
    window.addEventListener('resize', this.componentDidMount.bind(this))
  }

  @action componentDidMount(){
    if(this.refs.container){
      this.width = this.refs.container.offsetWidth
      this.height = this.refs.container.offsetHeight
    }
  }

  render(){
    /* eslint-disable indent */
    return pug`
      div(ref='container' style={width: '100%', height: '100%'})
        ${React.Children.map(this.props.children, child =>
          React.cloneElement(child, {[this.props.propWidth]: this.width, [this.props.propHeight]: this.height})
        )}
    `
  }
}
