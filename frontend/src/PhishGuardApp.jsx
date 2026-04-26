import React from 'react';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
import Login from './components/Login';
import Scanner from './components/Scanner';
import Alerts from './components/Alerts';
import Dashboard from './components/Dashboard';

const PhishGuardApp = () => {
    return (
        <Router>
            <Switch>
                <Route path='/' exact component={Login} />
                <Route path='/scanner' component={Scanner} />
                <Route path='/alerts' component={Alerts} />
                <Route path='/dashboard' component={Dashboard} />
            </Switch>
        </Router>
    );
};

export default PhishGuardApp;