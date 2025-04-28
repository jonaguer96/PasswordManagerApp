const passwordInput = document.getElementById('password');
const strengthText = document.getElementById('strength');

passwordInput.addEventListener('input', () => {
    const value = passwordInput.value;
    if (value.length < 6) {
        strengthText.innerText = 'Weak Password';
        strengthText.style.color = 'red';
    } else if (value.length < 10) {
        strengthText.innerText = 'Medium Strength';
        strengthText.style.color = 'orange';
    } else {
        strengthText.innerText = 'Strong Password';
        strengthText.style.color = 'green';
    }
});
