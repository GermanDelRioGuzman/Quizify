import { createClient } from '@supabase/supabase-js';

// Coloca tu URL de Supabase y la clave de API aquí
const supabaseUrl = 'https://yhlihozgegpresfywlnu.supabase.co'; // Tu URL de Supabase
const supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlobGlob3pnZWdwcmVzZnl3bG51Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjM0NzAxOTgsImV4cCI6MjAzOTA0NjE5OH0.tqJEncC8hNaj3cAr4eVC3WWG4ljruQBBOxHzSnGFydg'; // Tu clave pública de Supabase

// Crear un cliente de Supabase
const supabase = createClient(supabaseUrl, supabaseKey);

// Exportar el cliente para usarlo en otras partes de la aplicación
export default supabase;
