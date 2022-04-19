import React, { useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import store from '../store';

const Logout = () => {
    // normally, we would inform the server just in case.
    // (also, this wouldn't work if the cookie were httponly which it ought to be
    document.cookie = "auth_token=";
    useEffect(() => {
        store.dispatch({ type: "LOGOUT" });
    }, []);
    return (<Navigate to="/" />);
};

export default Logout;
