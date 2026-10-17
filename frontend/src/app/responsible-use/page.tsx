import type { Metadata } from "next";
import LegalPage from "@/components/legal/LegalPage";

export const metadata: Metadata = {
  title: "Uso responsable — CENTINELA",
  description:
    "CENTINELA es una herramienta defensiva: para proteger tus propias cuentas y dispositivos. Conoce los usos permitidos y prohibidos.",
};

export default function ResponsibleUsePage() {
  return (
    <LegalPage
      title="Uso responsable"
      updated="17 de octubre de 2026"
      sections={[
        {
          heading: "Finalidad defensiva",
          body: "CENTINELA está diseñado para proteger: tu objetivo es verificar enlaces, correos, mensajes, códigos QR, archivos e imágenes que te llegan a ti, así como comprobar la seguridad de tus propios servicios y dispositivos. Úsalo para defenderte, para aprender y para tomar mejores decisiones digitales.",
        },
        {
          heading: "Usos permitidos",
          body: "Está permitido analizar contenido que hayas recibido, que sea tuyo o sobre el que tengas autorización expresa: un enlace de un mensaje sospechoso, el correo que pide tus datos bancarios, tu propia red o servidor. También está permitido usar las herramientas con fines educativos y de concientización sobre seguridad.",
        },
        {
          heading: "Usos prohibidos",
          body: "Está prohibido usar CENTINELA para analizar, escanear o sondear sistemas, redes o cuentas de terceros sin su autorización; para acosar, vigilar o espiar personas; para investigar a alguien sin una base legítima; o para cualquier actividad ilegal en tu jurisdicción. Tampoco subas malware activo, datos robados o credenciales de otras personas.",
        },
        {
          heading: "Cómo interpretar los resultados",
          body: "Los análisis de CENTINELA son orientativos y pueden contener falsos positivos o falsos negativos: ninguna herramienta detecta el 100% de las amenazas. El análisis de manipulación con IA se basa en metadatos y no es una prueba forense. Antes de bloquear a alguien, denunciar o tomar una decisión grave, confirma con fuentes adicionales y con criterio humano.",
        },
        {
          heading: "Privacidad de terceros",
          body: "Respeta la privacidad de otras personas: evita analizar contenido privado de terceros sin consentimiento y cumple las leyes locales, las políticas de tus plataformas y cualquier acuerdo interno que te aplique.",
        },
        {
          heading: "Abuso del servicio",
          body: "El uso abusivo de CENTINELA —por ejemplo, sondeos masivos no autorizados o uso que comprometa la seguridad o disponibilidad del servicio— puede derivar en la suspensión de funciones, restricción del acceso o cierre de la cuenta, además de las consecuencias legales que correspondan.",
        },
      ]}
    />
  );
}
