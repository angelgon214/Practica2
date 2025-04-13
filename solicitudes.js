const axios = require('axios');

const API_URL = "https://practica2-i59e.onrender.com/api/register";


const registerUser = async (username, email, password) => {
  try {
    const response = await axios.post(API_URL, {
      username,
      email,
      password
    });

    console.log("Registro exitoso:", response.data);
  } catch (error) {
    if (error.response) {
      if (error.response.status === 429) {
        
        console.error("Error: Demasiadas peticiones. Intenta de nuevo más tarde.");
      } else {
        console.error("Error al registrar el usuario:", error.response.data.message);
      }
    } else if (error.request) {
      
      console.error("No se recibió respuesta del servidor.");
    } else {
      
      console.error("Error al realizar la solicitud:", error.message);
    }
  }
};


const simulateRegistrations = async () => {
  for (let i = 500; i < 600; i++) {
    const username = `user${i}`;
    const email = `user${i}@example.com`;
    const password = "password123";

    console.log(`Realizando registro ${i + 1}`);
    await registerUser(username, email, password);

    
    await new Promise(resolve => setTimeout(resolve, 500));
  }
};


simulateRegistrations();
