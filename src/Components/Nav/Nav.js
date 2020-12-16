import React, { Component } from 'react';
import axios from 'axios';
import homeLogo from './../../assets/home_logo.png';
import newLogo from './../../assets/new_logo.png';
import logoutLogo from './../../assets/shut_down.png';
import './Nav.css';
import {Link, withRouter} from 'react-router-dom';
import {connect} from 'react-redux'
import {updateUser, logout} from '../../ducks/reducer'

class Nav extends Component {
  constructor() {
    super();

    this.state = {
      author: '',
      author_pic: '',
      title: '',
      img: '',
      content: '',
      loading: true,
      // username: '',
      // profile_pic: ''
    }

    this.logout = this.logout.bind(this);
    this.getUser = this.getUser.bind(this);
  }

  componentDidMount() {
    this.getUser()
  }

  getUser() {
    axios.get('/api/auth/me')
    .then(res => {
      console.log(res.data)
      this.setState ({...res.data})
      })
  }
  
  logout() {
    axios.post('/api/auth/logout')
      .then(_ => {
        console.log('Logout successful. See you soon.')
        this.setState({
          author: '',
          author_pic: '',
          title: '',
          img: '',
          content: '',
          loading: true,
          username: '',
          profile_pic: ''
        })
      })
  }
   
  render() {
    console.log(this.props)
    console.log(this.state.profile_pic)
      return this.props.location.pathname !== '/' &&
        <div className='nav'>
          <div className='nav-profile-container'>
            <div className='nav-profile-pic' style={{backgroundImage: `url(${this.state.profile_pic})`}}></div>
            <p>{this.state.username}</p>
          </div>
          <div className='nav-links'>
            <Link to='/dash'>
              <img className='nav-img' src={homeLogo} alt='home' />
            </Link>
            <Link to='/form'>
              <img className='nav-img' src={newLogo} alt='new post' />
            </Link>
          </div>
          <Link to='/' onClick={() => {this.logout()}}>
            <img className='nav-img logout' src={logoutLogo} alt='logout' />
          </Link>
        </div>
  }
}

function mapStateToProps(state) {
  return {
    updateUser: state.updateUser,
    logout: state.logout
  }
}

export default withRouter(connect(mapStateToProps, {updateUser, logout})(Nav));