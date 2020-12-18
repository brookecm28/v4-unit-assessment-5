import {Switch, Route} from 'react-router-dom'
import React from 'react'
import Auth from './Components/Auth/Auth'
import Dash from './Components/Dash/Dash'
import Form from './Components/Form/Form'
import Post from './Components/Post/Post'

export default (
    <Switch>
        <Route exact path='/' component={Auth} />
        <Route exact path='/dash' component={Dash} />
        <Route exact path='/api/post/:id' component={Post} />
        <Route exact path='/form' component={Form} />
    </Switch>
)