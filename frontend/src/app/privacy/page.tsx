import type { Metadata } from "next";
import LegalPage from "@/components/legal/LegalPage";

export const metadata: Metadata = {
  title: "Privacidad — GUARDIA FLOW",
  description:
    "Qué datos guarda Guardia Flow, cómo procesa los contenidos que analizas, qué terceros intervienen y cómo pedir la eliminación de tus datos.",
};

export default function PrivacyPage() {
  return (
    <LegalPage
      title="Privacidad"
      updated="17 de octubre de 2026"
      sections={[
        {
          heading: "El responsable del tratamiento de datos",
          body: "Responsable del tratamiento: [Nombre legal o razón social], domiciliado en [Dirección fiscal completa], [País]. Identificación fiscal: [RFC / ID fiscal]. Delegado de protección de datos / contacto de privacidad: soporte@guardiaflow.com.",
        },
        {
          heading: "Qué datos guardamos",
          body: "Guardamos los datos mínimos necesarios para operar el servicio: tu correo electrónico de cuenta, tu contraseña (almacenada únicamente como hash, nunca en texto plano), la fecha de registro y un historial de los análisis que realizas (tipo de análisis e indicador analizado, por ejemplo la URL o el asunto de un correo) para mostrarte tu panel y recomendaciones.",
        },
        {
          heading: "Contenido que analizas",
          body: "Los enlaces, textos, archivos o imágenes que envías se procesan para producir el resultado de análisis. El contenido no se conserva como parte de tu historial una vez entregado el resultado, salvo registros operativos temporales del sistema y salvo que tú guardes un informe en tu panel. Evita enviar información innecesariamente sensible: analiza el indicador concreto (la URL, el texto del mensaje), no documentos completos con datos de terceros.",
        },
        {
          heading: "Lo que jamás almacenamos",
          body: "No almacenamos tus contraseñas de otros servicios ni el contenido de tus archivos después del análisis. La verificación de filtraciones usa el método k-anonimato de Have I Been Pwned: tu contraseña nunca sale completa de tu dispositivo. Además, Guardia Flow nunca te pedirá credenciales de terceros para «protegerte»: si alguien lo hace, es una estafa.",
        },
        {
          heading: "Tu sesión",
          body: "Al iniciar sesión, tu navegador guarda un token de acceso en el almacenamiento local (localStorage) para mantener tu sesión activa sin pedirte la contraseña en cada visita. Cierra sesión en dispositivos compartidos y mantén tu navegador actualizado.",
        },
        {
          heading: "Terceros",
          body: "Los pagos se procesan a través de Stripe, que recibe los datos necesarios para cobrar tu suscripción conforme a su propia política de privacidad. Las consultas de inteligencia de amenazas (Google Web Risk, urlscan.io, AbuseIPDB, cuando están configuradas) envían a esos proveedores únicamente el indicador que estás buscando (por ejemplo, la URL o la dirección IP concreta). El asistente de IA puede procesar tus preguntas con un proveedor de modelos de lenguaje configurado por el operador del servicio.",
        },
        {
          heading: "Cookies y caché de la app",
          body: "Guardia Flow funciona como aplicación web progresiva (PWA): tu navegador puede guardar en caché recursos de la aplicación para que cargue rápido y pueda instalarse en tu pantalla de inicio. No usamos cookies de seguimiento ni publicidad de terceros.",
        },
        {
          heading: "Tus derechos y eliminación de datos",
          body: "Puedes solicitar en cualquier momento una copia de tus datos o su eliminación definitiva escribiendo a soporte@guardiaflow.com desde tu correo de cuenta. También puedes eliminar tu historial de análisis desde tu panel. Trataremos las solicitudes conforme a la legislación de protección de datos aplicable.",
        },
      ]}
    />
  );
}
